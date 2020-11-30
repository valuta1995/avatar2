from enum import IntEnum
from typing import Callable, Dict, List

from avatar2 import Avatar, BreakpointHitMessage, Target

VECTOR_TABLE_SIZE = 256

def mem_copy(target: Target, src: int, dst: int, word_size: int, num_words: int):
    print("Copying %d (0x%X) bytes\n\tfrom 0x%X ~ 0x%X\n\tto 0x%X ~ 0x%X" % (
        num_words * word_size,
        num_words * word_size,
        src,
        src + num_words * word_size,
        dst,
        dst + num_words * word_size,
    ))
    dump = target.read_memory(src, word_size, num_words=num_words)
    target.write_memory(dst, word_size, dump, num_words=num_words)


class VectorTableEntries(IntEnum):
    RESET = 0x04
    NMI = 0x08
    HARD_FAULT = 0x0C
    MEMORY_MANAGEMENT_FAULT = 0x10
    BUS_FAULT = 0x14
    USAGE_FAULT = 0x18
    # Missing entry 0x1C
    # Missing entry 0x20
    # Missing entry 0x24
    # Missing entry 0x28
    SVC = 0x2C
    DEBUG_MON = 0x30
    # Missing entry 0x34
    PEND_SV = 0x38
    SYS_TICK = 0x3C


CALLABLE_TYPE = Callable[[Target], bool]


class FaultDispatcher:
    _target: Target
    registered_irqs: Dict[int, List[CALLABLE_TYPE]]
    registered_breakpoints: Dict[int, int]
    fallback_callback: CALLABLE_TYPE
    post_vtor_execute_queue: List[int]

    initialized: bool
    vtor_ready: bool
    mpu_address: int
    vtor_address: int
    vtor_watch_id: int
    watchman: None
    next_free: int
    assembly: str
    assembly_bytes: int
    assembly_offset: int

    substitute_vt_addr: int
    substitute_handler_addr: int
    original_vt_addr: int

    def __init__(self, target: Target):
        self._target = target
        self.registered_irqs = dict()
        self.registered_breakpoints = dict()
        self.fallback_callback = self._default_fallback_callback
        self.post_vtor_execute_queue = list()

        # Fields to be set in manual initialization
        self.initialized = False
        self.vtor_ready = False
        self.mpu_address = 0
        self.vtor_address = 0
        self.vtor_watch_id = -1
        self.watchman = None
        self.next_free = 0
        self.substitute_vt_addr = 0
        self.substitute_handler_addr = 0

        # Fields set elsewhere
        self.original_vt_addr = 0

    def external_init(self, mpu_address: int, vtor_address: int, next_free_memory_addr: int, assembly: str,
                      assembly_bytes: int, assembly_offset: int):
        self.initialized = True
        self.mpu_address = mpu_address
        self.vtor_address = vtor_address
        self.vtor_watch_id = self._target.set_watchpoint(self.vtor_address)
        avatar: Avatar = self._target.avatar
        self.watchman = avatar.watchmen.add_watchman('BreakpointHit', when='before', callback=self.vtor_changed)
        self.assembly = assembly
        self.assembly_bytes = assembly_bytes
        self.assembly_offset = assembly_offset

        self.next_free = next_free_memory_addr
        print("Next free is at: 0x%X" % self.next_free)
        self.substitute_vt_addr = self.allocate_aligned(VECTOR_TABLE_SIZE * 4)
        print("VT is allocated at 0x%X" % self.substitute_vt_addr)
        print("Next free is at: 0x%X" % self.next_free)
        # self.substitute_handler_addr = self.allocate(assembly_bytes)
        # print("Handler is allocated at 0x%X" % self.substitute_handler_addr)
        # print("Next free is at: 0x%X" % self.next_free)

    def allocate(self, size):
        addr = self.next_free
        self.next_free += size
        return addr

    def allocate_aligned(self, size):
        addr = self.next_free
        bytes_too_high = addr % size
        if bytes_too_high == 0:
            return self.allocate(size)
        bytes_too_low = size - bytes_too_high
        self.next_free += bytes_too_low
        addr = self.next_free
        if addr % size != 0:
            raise Exception("Glenn, you fucked up.")
        return self.allocate(size)

    def vtor_changed(self, avatar: Avatar, message: BreakpointHitMessage):
        if not self.initialized:
            raise Exception("Fault dispatcher needs to be initialized before use.")
        # https://github.com/valuta1995/avatar2/blob/master/avatar2/protocols/coresight.py

        if message.breakpoint_number != -1 and message.breakpoint_number != self.vtor_watch_id:
            raise Exception("Breakpoint hit before watchpoint of VTOR, unsupported by this plugin.")

        # For now we only care about a single VTOR change at the start, remove callback
        # TODO consider extending to any amount of VTOR changes
        avatar.watchmen.remove_watchman('BreakpointHit', self.watchman)
        self.watchman = None

        # Now we should be watching for breakpoints that we are watching
        self.watchman = avatar.watchmen.add_watchman(
            'BreakpointHit',
            when='before',
            callback=self.on_breakpoint
        )

        target: Target = message.origin
        changed_vt_addr = target.read_memory(self.vtor_address, 4)
        self.original_vt_addr = changed_vt_addr
        target.log.info(
            "VTOR was written by 0x%X.\n"
            "\tIt was moved to 0x%X.\n"
            "\tI moved it to 0x%x" % (
                message.address,
                changed_vt_addr,
                self.substitute_vt_addr,
            )
        )
        mem_copy(target, changed_vt_addr, self.substitute_vt_addr, 4, num_words=VECTOR_TABLE_SIZE)
        target.write_memory(self.vtor_address, 4, self.substitute_vt_addr)
        self.vtor_ready = True
        for irq_offset in self.post_vtor_execute_queue:
            print("Executing delayed listen for iqr 0x%X." % irq_offset)
            self._actually_listen_for_irq(irq_offset)

    def _default_fallback_callback(self):
        print(self.vtor_watch_id)
        return True

    def listen_for_irq(self, irq_vt_offset: int):
        if not self.initialized:
            raise Exception("Fault dispatcher needs to be initialized before use.")

        if irq_vt_offset in self.registered_irqs:
            raise Exception("IRQ 0x%X is already registered" % irq_vt_offset)

        # Mark the registration as active to prevent double registers later even if not vtor_ready
        self.registered_irqs[irq_vt_offset] = list()

        if not self.vtor_ready:
            print("Delaying 0x%X until post vtor-setup." % irq_vt_offset)
            self.post_vtor_execute_queue.append(irq_vt_offset)
            return

        self._actually_listen_for_irq(irq_vt_offset)

    def _actually_listen_for_irq(self, irq_vt_offset):
        original_vt_entry = self.original_vt_addr + irq_vt_offset
        original_handler_addr = self._target.read_memory(original_vt_entry, 4)
        new_handler_addr = self.allocate(self.assembly_bytes)
        substitute_vt_entry = self.substitute_vt_addr + irq_vt_offset
        # TODO why does +1/+3 work (with wrong thumb-ness) but +0/+2 break completely
        self._target.write_memory(substitute_vt_entry, 4, new_handler_addr + 1)
        print("New handler at 0x%X registered to 0x%X" % (new_handler_addr, substitute_vt_entry))
        # self._target.set_breakpoint(original_handler_addr)
        # breakpoint_number = self._target.set_breakpoint(new_handler_addr)
        breakpoint_number = self._target.set_breakpoint(new_handler_addr + self.assembly_offset)
        self.registered_breakpoints[breakpoint_number] = irq_vt_offset
        self._target.log.info("Set breakpoints 0x%X" % (new_handler_addr + self.assembly_offset))
        self.assemble_handler(new_handler_addr, irq_vt_offset)
        print("Injected new handler for 0x%X" % irq_vt_offset)

    def assemble_handler(self, handler_addr: int, handler_offset: int):
        asm_string = self.assembly % (
            self.original_vt_addr,
            handler_offset,
            self.mpu_address,
            self.mpu_address,
        )
        print(asm_string)
        if hasattr(self._target, 'inject_asm'):
            success = self._target.inject_asm(asm_string, addr=handler_addr)
            if not success:
                raise Exception("Error during assembly injection")
        else:
            raise Exception("Assembler is not available, please avatar.load_plugin('assembler').")

    def on_breakpoint(self, avatar: Avatar, message: BreakpointHitMessage):
        breakpoint_id = message.breakpoint_number
        # Is this breakpoint registered at all?
        if breakpoint_id not in self.registered_breakpoints:
            return
        # If so, record the expected irq offset
        expected_irq_offset = self.registered_breakpoints[breakpoint_id]

        target: Target = message.origin
        target.log.info("A registered IRQ was intercepted on PC=0x%X" % target.read_register('pc'))

        # Get the IRQ id as reported by the system and calculat the offset
        reported_irq_id = target.read_register('xPSR') & 0xFF
        reported_irq_offset = reported_irq_id * 0x4

        # Make sure that the breakpoint we hit matches the IRQ reported by the system.
        if reported_irq_offset != expected_irq_offset:
            raise Exception("Hit a breakpoint for IRQ-offset 0x%X while system should be in offset 0x%X" % (
                expected_irq_offset, reported_irq_offset
            ))

        callbacks = self.registered_irqs[reported_irq_offset]
        callback: CALLABLE_TYPE
        success: bool = False
        for callback in callbacks:
            success = callback(target)
            if success is True:
                break
        if success:
            print("Exception no.%d (0x%X) was handled." % (reported_irq_id, reported_irq_offset))
        else:
            print("Exception no.%d (0x%X) was not handled." % (reported_irq_id, reported_irq_offset))

    def add_on_irq_callback(self, irq_vector: int, callback: CALLABLE_TYPE):
        if irq_vector not in self.registered_irqs:
            raise Exception("Listening for 0x%X callbacks is not enabled" % irq_vector)
        self.registered_irqs[irq_vector].append(callback)


def on_breakpoint_hit(avatar: Avatar, message: BreakpointHitMessage) -> None:
    target: Target = message.origin
    if hasattr(target, 'fault_dispatcher'):
        fault_dispatcher: FaultDispatcher = target.fault_dispatcher
        fault_dispatcher.is_this_a_fault(message)
    else:
        raise Exception("Function should not be called without the attribute being set.")


def load_plugin(avatar: Avatar) -> None:
    # avatar.watchmen.add_watchman('BreakpointHit', when='before', callback=on_breakpoint_hit)
    target: Target
    for target in avatar.targets.values():
        target.fault_dispatcher = FaultDispatcher(target)
