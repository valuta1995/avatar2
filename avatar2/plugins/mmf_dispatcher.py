from typing import Callable, List

from avatar2 import Target, ARM_CORTEX_M3, Avatar, BreakpointHitMessage

CALLBACK_TYPE = Callable[[Target], bool]


class MemFaultDispatcher:
    _target: Target

    _vt_base: int
    _vtor_wp_id: int

    _hf_handler_addr: int
    _vt_hf_value: int
    _vt_hf_bp_id: int
    _vt_hf_wp_id: int

    _mmf_handler_addr: int
    _vt_mmf_value: int
    _vt_mmf_bp_id: int
    _vt_mmf_wp_id: int

    _callbacks: List[CALLBACK_TYPE]

    def __init__(self, target: Target):
        self._target = target

        # We want to intercept several watch/break-points, all of which will propagate through the avatar watchmen:
        self._target.avatar.watchmen.add_watchman('BreakpointHit', when='before', callback=self.on_breakpoint_hit)

        # Most importantly is the watchpoint on the Vector Table Offset Register.
        # If this value changes we need to update the other breakpoints as well.
        self._vtor_wp_id = self._target.set_watchpoint(self.arch.VTOR.ADDRESS, write=True, read=False)

        # Now I set bogus values for the rest so they will be populated.
        self._vt_base = -1

        self._hf_handler_addr = -1
        self._vt_hf_bp_id = -1
        self._vt_hf_wp_id = -1

        self._mmf_handler_addr = -1
        self._vt_mmf_bp_id = -1
        self._vt_mmf_wp_id = -1

        self.count_skipped_breakpoints = 0

        # This will be done in late init (after the target has initialized)
        # TODO bind this to target init events with watchmen.
        # self._ensure_vt_consistency()

        self._callbacks = list()

    def late_init(self):
        self._ensure_vt_consistency()

    @property
    def arch(self) -> ARM_CORTEX_M3:
        return self._target.avatar.arch

    def on_breakpoint_hit(self, avatar: Avatar, message: BreakpointHitMessage):
        if avatar is not self._target.avatar:
            raise Exception("Wrong avatar instance.")

        if message.origin is not self._target:
            # TODO if this is too aggressive for multi-target systems replace with return.
            raise Exception("Wrong target on breakpoint hit.")

        bp_addr = message.address
        bp_id = message.breakpoint_number

        if bp_id in [self._vtor_wp_id, self._vt_hf_wp_id, self._vt_mmf_wp_id]:
            self._target.log.info("VTOR was written to by 0x%X, update consistency." % bp_addr)
            self._ensure_vt_consistency()

        elif bp_id in [self._vt_hf_bp_id, self._vt_mmf_bp_id]:
            self._target.log.info("HF or MMF breakpoint triggered by 0x%X." % bp_addr)
            if self._check_if_mmf():
                self._trigger_dispatch()
            else:
                self.count_skipped_breakpoints += 1

        elif bp_id == -1:
            self._target.log.warn("BP id == -1, assuming VTOR/Entry may have been edited by 0x%X." % bp_addr)
            self._ensure_vt_consistency()

        else:
            self._target.log.info("Dispatcher disregarding breakpoint with ID: %d at 0x%X" % (bp_id, bp_addr))

    def _trigger_dispatch(self):
        marked_for_delete = list()
        for callback in self._callbacks:
            remove_me = callback(self._target)
            if remove_me:
                marked_for_delete.append(callback)

        for callback in marked_for_delete:
            self._callbacks.remove(callback)

    def add_callback(self, callback: CALLBACK_TYPE):
        self._callbacks.append(callback)

    def _check_if_mmf(self):
        vt_entry_offset = 4 * self.arch.ICSR.read_active_vector(self._target)
        if vt_entry_offset == 0x10:
            # We are currently in a MMF handler state, definitely true.
            return True

        elif vt_entry_offset == 0x0C:
            # We are in a hard fault state, this is cause directly by a memory management fault IFF:
            #  - The HF is forced (i.e. caused by another fault that could not fire)
            #  - Some MMF flag is active
            #  - The MMF is not simply pended
            hf_was_forced = 0 != (self.arch.HFSR.read(self._target) & self.arch.HFSR.MASK_FORCED)
            mmf_flags = 0 != (self.arch.CFSR.read(self._target) & 0xFF)  # Read only the last 8 bits (mmf)
            mmf_pended = 0 != (self.arch.SHCSR.read(self._target) & self.arch.SHCSR.MASK_MEM_FAULT_PENDING)

            return hf_was_forced and mmf_flags and not mmf_pended

        else:
            raise Exception("We should not be in this situation at all... (vt_offset is 0x%X)" % vt_entry_offset)

    def _unset_breakpoint(self, bp_id: int):
        if bp_id == -1:
            return  # Not set, do nothing
        self._target.remove_breakpoint(bp_id)

    def _ensure_vt_consistency(self):
        vector_table_base = self.arch.VTOR.read(self._target)

        hf_entry_addr = vector_table_base + 0x0C
        mmf_entry_addr = vector_table_base + 0x10

        hf_handler_addr = self._target.read_memory(hf_entry_addr, 4)
        mmf_handler_addr = self._target.read_memory(mmf_entry_addr, 4)

        if vector_table_base != self._vt_base:
            self._target.log.info("VTOR was changed. Updating entry watchpoints.")
            # Unset old ones
            self._unset_breakpoint(self._vt_hf_wp_id)
            self._unset_breakpoint(self._vt_mmf_wp_id)
            # Set new ones
            self._vt_hf_wp_id = self._target.set_watchpoint(hf_entry_addr)
            self._vt_mmf_wp_id = self._target.set_watchpoint(mmf_entry_addr)

        if hf_handler_addr != self._hf_handler_addr:
            self._target.log.info("Hard-fault handler address changed. Updating HF handler breakpoint.")
            self._unset_breakpoint(self._vt_hf_bp_id)
            thumbed = hf_handler_addr & ~1
            self._vt_hf_bp_id = self._target.set_breakpoint(thumbed)
            print("\tHF handler is at 0x%X" % thumbed)

        if mmf_handler_addr != self._mmf_handler_addr:
            self._target.log.info("Memory-management-fault handler address changed. Updating MMF handler breakpoint.")
            self._unset_breakpoint(self._vt_mmf_bp_id)
            thumbed = mmf_handler_addr & ~1
            self._vt_mmf_bp_id = self._target.set_breakpoint(thumbed)
            print("\tMMF handler is at 0x%X" % thumbed)


def load_plugin(avatar: Avatar) -> None:
    target: Target
    for name, target in avatar.targets.items():
        target.mmf_dispatcher = MemFaultDispatcher(target)
