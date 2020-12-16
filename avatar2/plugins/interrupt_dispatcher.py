from typing import Dict, List, Callable

from avatar2 import Target, Avatar, ARM_CORTEX_M3, BreakpointHitMessage

# A small ASM snippet that reflects an intercepted IRQ back on track
CALLBACK_TYPE = Callable[[Target], bool]

# After ASM_IRQ_MIRROR_HEAD
# R0 := original_handler_address
# R1 := mpu_cr_address
# R2 := mpu_enable_flag
#
# Injection order
#   ICSR.ADDRESS
#   ICSR.MASK_VECT_ACTIVE
#   size_number
#   vt_address
#   MpuCR.ADDRESS
#   MpuCR disable flag
#   MpuCR enable flag
ASM_IRQ_MIRROR_HEAD = (
    "Avatar2Trampoline:\n"
    # Load R1 = ICSR_ADDR (inject address of reg with active interrupt)
    "LDR    R1, =0x%X\n"
    # Load R1 = *R1 (icsr_value = *ICSR_ADDR)
    "LDR    R1, [R1]\n"

    # Load R0 = ICSR_ACTIVE_MASK (inject the mask for which bytes signal an active interrupt)
    "LDR    R0, =0x%X\n"

    # Mask R1 = R1 & R0 (active_irq_no = icsr_value & ICSR_ACTIVE_MASK)
    "AND    R1, R1, R0\n"
    # Shift R1 = R1 << ptr_size (injected size of vtable_entries 0: 1-byte, 1: 2-byte, 2: 4-byte)
    "LSL    R1, R1, #%d\n"

    # Load R0 = VTABLE_ADDR (injected vtable address)
    "LDR    R0, =0x%X\n"
    # Load R0 = R0[R1] (handler_fn_ptr = vtable[offset])
    "LDR    R0, [R0, R1]\n"

    "Avatar2DisableMPU:\n"
    "DMB    sy\n"
    # Load R0 = MPU_CR_ADDR (injected MpuCR address)
    "LDR    R1, =0x%X\n"
    # Load R2 = MPU_DISABLE_FLAG (injected disable flag)
    "LDR    R2, =0x%X\n"
    # Disable the MPU
    "STR    R2, [R1]\n"
    # Load R2 = MPU_ENABLE_FLAG (injected enable_flag)
    "LDR    R2, =0x%X\n"
)

ASM_IRQ_MIRROR_TAIL = (
    "BKPT\n"
    "NOP\n"
    "NOP\n"
    "NOP\n"  
    
    "Avatar2EnableMPU:\n"
    "DSB    sy\n"
    "ISB    sy\n"
    "STR    R2, [R1]\n"
    "BX     R0\n"
)

ASM_IRQ_MIRROR_TAIL_ALT = (
    "BKPT\n"
    "%s\n"
    "%s\n"
    "%s\n"  
    
    "Avatar2EnableMPU:\n"
    "DSB    sy\n"
    "ISB    sy\n"
    "STR    R2, [R1]\n"
    "BX     R0\n"
)

ASM_IRQ_MIRROR_NOP = (
    "NOP\n"
    "NOP\n"
    "NOP\n"
    "NOP\n"
    "NOP\n"
    "NOP\n"
    "NOP\n"
    "NOP\n"
)

ASM_IRQ_MIRROR = ASM_IRQ_MIRROR_HEAD + ASM_IRQ_MIRROR_TAIL + ASM_IRQ_MIRROR_NOP

# TODO this only works for IR handlers that do not need access to the stack (corrupt LR?)
# ICSR.ADDRESS, ICSR.MASK_VECT_ACTIVE, 2, OG result of VTOR.read(), MpuCR, 0x0
ASM_FREE_IRQ_MIRROR = (
    ".thumb\n"
    "Avatar2Trampoline:\n"
    "LDR    R2, =0x%X\n"  # Inject ICSR
    "LDR    R2, [R2]\n"  # Get the value from the ICSR
    "LDR    R3, =0x%X\n"  # Inject ICSR's mask for active vector
    "AND    R2, R2, R3\n"  # Mask the value from ICSR 
    "LSL    R2, R2, #%d\n"  # Inject for word size 0: 1-byte, 1: 2-byte, 2: 4-byte
    "LDR    R3, =0x%X\n"  # Inject OG VT address
    "LDR    R1, [R3, R2]\n"  # Get the start of the OG handler

    "DMB    sy\n"
    "LDR    R3, =0x%X\n"  # Inject MPU control register addr
    "LDR    R2, =0x%X\n"  # Inject MPU disable flag
    "STR    R2, [R3]\n"  # Disable the MPU

    "BKPT\n"
    "DSB    sy\n"
    "ISB    sy\n"
    "NOP\n"
    "BLX    R1\n"  # Run the OG handler
    "NOP\n"

    "LDR    R2, =0x%X\n"  # Inject MPU enable flag
    "STR    R2, [R3]\n"  # Enable the MPU
    "DSB    sy\n"
    "ISB    sy\n"

    "BX     lr\n"
)


def build_irq_mirror_asm_string(
        icsr_address: int, icsr_active_mask: int, entry_size: int, vtor_address: int,
        mpu_address: int, mpu_disable_value: int, mpu_enable_value: int
):
    if entry_size == 1:
        size_num = 0
    elif entry_size == 2:
        size_num = 1
    elif entry_size == 4:
        size_num = 2
    elif entry_size == 8:
        size_num = 3
    else:
        raise Exception("Invalid size for vt entry")
    return ASM_IRQ_MIRROR % (
        icsr_address,
        icsr_active_mask,
        size_num,
        vtor_address,
        mpu_address,
        mpu_disable_value,
        mpu_enable_value,
    )


class RegisteredVector:
    vector_offset: int
    callbacks: List[CALLBACK_TYPE]

    def __init__(self, offset: int):
        self.vector_offset = offset
        self.callbacks = list()

    def trigger(self, target: Target):
        delete_list = list()
        for callback in self.callbacks:
            remove_me = callback(target)
            if remove_me:
                delete_list.append(callback)

        for callback in delete_list:
            self.callbacks.remove(callback)

    def add_callback(self, callback: CALLBACK_TYPE):
        self.callbacks.append(callback)


class InterruptDispatcher:
    _target: Target
    _arch: ARM_CORTEX_M3

    _registered_vectors: Dict[int, RegisteredVector]

    _og_vt_addr: int
    _vtor_wp_id: int

    _late_init: bool

    _memory_range_start: int
    _memory_range_free: int
    _memory_range_end: int

    _substitute_vt_addr: int
    _substitute_vt_size: int
    _substitute_handler_addr: int
    _substitute_handler_size: int

    def __init__(self, target: Target):
        """
        if hasattr(self._arch, 'VTOR'):
            current_vt_addr = self._arch.VTOR.write(self._target, self._substitute_vt_addr)
        else:
            self._target.log.warn("Arch has no VTOR info, unable to store substitute VT addr")
        target: The target to which the dispatcher is attached
        """
        self._target = target
        self._arch = target.avatar.arch

        self._registered_vectors = dict()

        self._og_vt_addr = self._get_vt_addr()
        vtor_location = self._get_vtor_addr()
        if vtor_location is not None:
            self._vtor_wp_id = self._target.set_watchpoint(vtor_location)
        else:
            self._vtor_wp_id = -1
        self._target.avatar.watchmen.add_watchman('BreakpointHit', when='before', callback=self.on_breakpoint_hit)

        self._late_init = False

    def late_init(self, free_mem_start: int, free_mem_end: int):
        if self._late_init:
            raise Exception("Late init has already been called")
        self._late_init = True

        self._memory_range_start = free_mem_start
        self._memory_range_free = free_mem_start
        self._memory_range_end = free_mem_end

        addr, size = self._inject_vector_table()
        self._substitute_vt_addr = addr
        self._substitute_vt_size = size

        addr, size = self._inject_interrupt_handler()
        self._substitute_handler_addr = addr
        self._substitute_handler_size = size

    def on_breakpoint_hit(self, avatar: Avatar, message: BreakpointHitMessage):
        if not self._late_init:
            raise Exception("Late init must be called before this dispatcher is usable.")

        if avatar is not self._target.avatar:
            raise Exception("On breakpoint hit called for the wrong avatar instance.")

        if message.origin is not self._target:
            raise Exception("On breakpoint hit called for the wrong target instance.")

        bp_id = message.breakpoint_number

        if hasattr(self._arch, 'VTOR'):
            current_vt_addr = self._arch.VTOR.read(self._target)
            if current_vt_addr != self._substitute_vt_addr:
                if bp_id == -1:
                    self._target.log.warn("Breakpoint ID is not set but VTOR was changed")
                elif bp_id != self._vtor_wp_id:
                    self._target.log.warn("VTOR was changed outside of watchpoint domain")
                self._propagate_vtor_change(current_vt_addr)
        else:
            self._target.log.warn("Arch has no VTOR info, unable to track changes.")

        current_pc = self._target.read_register('pc')
        if self._substitute_handler_addr <= current_pc <= self._substitute_handler_addr + self._substitute_handler_size:
            self.on_handler_hit()

    def _inject_handler_into_vt(self, vt_offset):
        vt_entry_addr = self._substitute_vt_addr + vt_offset
        addr_in_vtable = self._substitute_handler_addr | 0x1
        self._target.write_memory(vt_entry_addr, 4, addr_in_vtable)

    def _propagate_vtor_change(self, new_addr):
        old_addr = self._og_vt_addr
        self._og_vt_addr = new_addr
        self._mem_copy(self._og_vt_addr, self._substitute_vt_addr, self._substitute_vt_size)

        if hasattr(self._arch, 'VTOR'):
            current_vt_addr = self._arch.VTOR.write(self._target, self._substitute_vt_addr)
        else:
            self._target.log.warn("Arch has no VTOR info, unable to store substitute VT addr")

        self._re_inject_interrupt_handler()

        for vt_offset, registered_vector in self._registered_vectors.items():
            self._inject_handler_into_vt(vt_offset)

    def _mem_copy(self, source, target, size):
        buf = self._target.read_memory(source, 1, size, raw=True)
        self._target.write_memory(target, 1, buf, size, raw=True)

    def enable_vector_listener(self, vector_index: int):
        if not self._late_init:
            raise Exception("Late init must be called before this dispatcher is usable")
        vt_offset = vector_index * 4
        if vt_offset in self._registered_vectors:
            raise Exception("Intercept for vector %d (off:0x%X) is already active." % (vector_index, vt_offset))
        self._registered_vectors[vt_offset] = RegisteredVector(vt_offset)
        self._inject_handler_into_vt(vt_offset)

    def register_vector_callback(self, vector_index: int, callback: CALLBACK_TYPE):
        if not self._late_init:
            raise Exception("Late init must be called before this dispatcher is usable")
        vt_offset = vector_index * 4
        if vt_offset not in self._registered_vectors:
            raise Exception("The vector offset you are trying to register a callback to is not handled.")
        self._registered_vectors[vt_offset].add_callback(callback)

    def _get_vt_addr(self):
        if hasattr(self._arch, 'VTOR'):
            vt_address = self._arch.VTOR.read(self._target)
        else:
            self._target.log.warn("No VTOR address found for the target architecture. Assuming 0x0")
            vt_address = 0x0
        return vt_address

    def _get_vtor_addr(self):
        if hasattr(self._arch, 'VTOR'):
            vt_address = self._arch.VTOR.ADDRESS
        else:
            self._target.log.warn("No VTOR address found for the target architecture.")
            vt_address = None
        return vt_address

    def _allocate(self, size: int) -> int:
        address = self._memory_range_free
        if address > self._memory_range_end:
            raise MemoryError("Target is out of 'free' memory.")
        self._memory_range_free += size
        return address

    def _allocate_aligned(self, size: int) -> int:
        address = self._memory_range_free
        overflow = address % size
        if overflow == 0:
            return self._allocate(size)
        underflow = size - overflow
        self._memory_range_free += underflow

        address = self._memory_range_free
        overflow = address % size
        if overflow == 0:
            return self._allocate(size)
        else:
            raise Exception("Developer issue in basic arithmetic @glenn")

    def _inject_vector_table(self):
        if hasattr(self._arch, 'AMOUNT_OF_EXCEPTIONS'):
            num_interrupts = self._arch.AMOUNT_OF_EXCEPTIONS
        else:
            self._target.log.warn("Architecture has no known number of exceptions, assuming 64")
            num_interrupts = 64

        if hasattr(self._arch, 'ICTR'):
            num_interrupts += self._arch.ICTR.read_interrupts(self._target)
        else:
            self._target.log.warn("Architecture has no known register for number of interrupt, assuming 256")
            num_interrupts = 256

        vt_size = num_interrupts * 4
        vt_aligned_size = 1 << (vt_size - 1).bit_length()
        substitute_vt_address = self._allocate_aligned(vt_aligned_size)
        self._target.log.info("Allocated %d (0x%X) bytes for new vtable at 0x%X" % (
            vt_aligned_size, vt_aligned_size,
            substitute_vt_address
        ))

        self._mem_copy(self._og_vt_addr, substitute_vt_address, vt_aligned_size)
        if hasattr(self._arch, 'VTOR'):
            current_vt_addr = self._arch.VTOR.write(self._target, substitute_vt_address)
        else:
            self._target.log.warn("Arch has no VTOR info, unable to store substitute VT addr")

        return substitute_vt_address, vt_aligned_size

    def _inject_interrupt_handler(self):
        asm_string = self.get_formatted_asm()

        if hasattr(self._target, 'assemble') and hasattr(self._target, 'inject_asm'):
            raw_bytes = self._target.assemble(asm_string, addr=self._memory_range_free)
            num_bytes = len(raw_bytes)
            if num_bytes == 0:
                raise Exception("Failed to assemble the required instructions.")
            handler_address = self._allocate(num_bytes)
            success = self._target.inject_asm(asm_string, addr=handler_address)
            if not success:
                raise Exception("Error during assembly injection")
        else:
            raise Exception("Assembler is not available, please avatar.load_plugin('assembler').")

        return handler_address, num_bytes

    def get_formatted_asm(self):
        if hasattr(self._arch, 'ICSR') and hasattr(self._arch, 'MpuCR'):
            icsr_addr = self._arch.ICSR.ADDRESS
            icsr_mask = self._arch.ICSR.MASK_VECT_ACTIVE

            mpu_address = self._arch.MpuCR.ADDRESS
            mpu_disable_value = 0
            mpu_enable_value = self._arch.MpuCR.MASK_PRIV_DEF_ENA | self._arch.MpuCR.MASK_ENABLE
            asm_string = build_irq_mirror_asm_string(
                icsr_addr, icsr_mask, 4, self._og_vt_addr,
                mpu_address, mpu_disable_value, mpu_enable_value
            )
        else:
            raise Exception("Architecture has no info on ICSR register. Failed to inject interrupt handler")
        return asm_string

    def _re_inject_interrupt_handler(self):
        asm_string = self.get_formatted_asm()

        if hasattr(self._target, 'inject_asm'):
            success = self._target.inject_asm(asm_string, addr=self._substitute_handler_addr)
            if not success:
                raise Exception("Error during assembly injection")
        else:
            raise Exception("Assembler is not available, please avatar.load_plugin('assembler').")

    def on_handler_hit(self):
        if hasattr(self._arch, 'ICSR'):
            vector_id = self._arch.ICSR.read_active_vector(self._target)
        else:
            self._target.log.warn("No ICSR-like register cannot determine original vector")
            vector_id = 0
        vt_offset = vector_id * 4

        if vt_offset not in self._registered_vectors:
            self._target.log.warn("A handler was hit (0x%X) even though it seems to not be registered." % vt_offset)
        else:
            print("Hit a fault handler for offset 0x%X" % vt_offset)
            registered_vector = self._registered_vectors[vt_offset]
            if len(registered_vector.callbacks) == 0:
                self._target.log.warn("No callbacks registered. Are you sure is this intentional?")
            registered_vector.trigger(self._target)


def load_plugin(avatar: Avatar) -> None:
    target: Target
    for name, target in avatar.targets.items():
        target.interrupt_dispatcher = InterruptDispatcher(target)
