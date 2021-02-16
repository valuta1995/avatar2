from typing import List

from avatar2 import Avatar, Target, ARM_CORTEX_M3 as CM3

REGISTERS_ON_STACK = [
    'r0', 'r1', 'r2', 'r3', 'r12', 'lr', 'pc', 'psr'
]
SYSTEM_INTERRUPTS = [
    'MSP init addr', 'Reset', 'NMI', 'Hard fault',  # Unconfigurable system interrupts
    'MemManage fault', 'Bus fault', 'Usage fault',  # Configurable system interrupts
    '-reserved-', '-reserved-', '-reserved-', '-reserved-',  # Future work :p
    'SVC', 'Debug monitor', '-reserved-', 'PendSV', 'SYSTICK'  # Aux. system interrupts
]


class Interrupt:
    id: int
    vt_address: int
    handler_address: int
    name: str
    enabled: bool
    pended: bool
    active: bool
    priority: int

    def __init__(self, index, vt_base, vt_entry):
        self.id = index
        self.vt_address = vt_base + index * 4
        self.handler_address = vt_entry
        self.name = ""
        self.enabled = False
        self.pended = False
        self.active = False
        self.priority = 0


def insert_character_at(string, index):
    return string[:index] + "|" + string[index:]


def _interrupt_to_string(interrupt, prio_group_number):
    if interrupt.priority < 0:
        pri_str = " %d " % interrupt.priority
    else:
        pri_str = "{0:08b}".format(interrupt.priority)
        pri_str = insert_character_at(pri_str, 7 - prio_group_number)
    result = "%5s, %10s, %10s, %16s, %3s, %3s, %3s, %8s" % (
        "%d" % interrupt.id,
        "0x%08X" % interrupt.vt_address,
        "0x%08X" % interrupt.handler_address,
        interrupt.name,
        " + " if interrupt.enabled else "",
        " + " if interrupt.pended else "",
        " + " if interrupt.active else "",
        pri_str)
    return result


def pretty_print_interrupts(interrupts, prio_group_number):
    #      12345, 123456789a, 123456789a, 123456789abcdef0, 123, 123, 123, 12345678
    print("index, vt-entry  , handler   , Name            , Ena, Pnd, Act, Priority")
    for interrupt in interrupts:
        print(_interrupt_to_string(interrupt, prio_group_number))


def _print_stack_content(sp_value, offset, target):
    values_on_stack = target.read_memory(sp_value + offset, 4, 8)
    faulting_context = {REGISTERS_ON_STACK[i]: values_on_stack[i] for i in range(len(REGISTERS_ON_STACK))}
    for key, value in faulting_context.items():
        print("%4s: %10s" % (key, "0x%X" % value))


class CortexM3DumpTool:

    def __init__(self, target: Target):
        self._target = target

    def dump_all_fault(self):
        print("R0: 0x%X" % self._target.read_register('r0'))
        print("R1: 0x%X" % self._target.read_register('r1'))
        print("R2: 0x%X" % self._target.read_register('r2'))
        print("R3: 0x%X" % self._target.read_register('r3'))
        print("R4: 0x%X" % self._target.read_register('r4'))
        print("R5: 0x%X" % self._target.read_register('r5'))
        print("R6: 0x%X" % self._target.read_register('r6'))
        print("R7: 0x%X" % self._target.read_register('r7'))
        print("R8: 0x%X" % self._target.read_register('r8'))
        print("R9: 0x%X" % self._target.read_register('r9'))
        print("R10: 0x%X" % self._target.read_register('r10'))
        print("R11: 0x%X" % self._target.read_register('r11'))
        print("R12: 0x%X" % self._target.read_register('r12'))
        print("SP: 0x%X" % self._target.read_register('sp'))
        print("LR: 0x%X" % self._target.read_register('lr'))
        print("PC: 0x%X" % self._target.read_register('pc'))
        print("PSP: 0x%X" % self._target.read_register('psp'))
        print("MSP: 0x%X" % self._target.read_register('msp'))

        psr_value = self._target.read_register('xPSR')
        print("┌─Negative flag")
        print("│┌─Zero flag")
        print("││┌─Carry flag")
        print("│││┌─Overflow flag")
        print("││││┌─Saturation flag")
        #     '10101010101010101010101010101010'
        print("{:>032b}".format(psr_value))
        #     '10101010101010101010101010101010'
        print("ICI: ^^│        ^^^^^^││││││││││")
        print("Thumb: ^              ││││││││││")
        print("                 ISR: ^^^^^^^^^^")
        
        primask_value = self._target.read_register('primask')
        print("Primask is " + ("active" if primask_value != 0 else "inactive"))
        
        faultmask_value = self._target.read_register('faultmask')
        print("faultmask is " + ("active" if faultmask_value != 0 else "inactive"))

        basepri_value = self._target.read_register("basepri")
        print("basepri = %d" % basepri_value)

        control_value = self._target.read_register("control")
        spsel = "msp" if (control_value & 0b10) == 0 else "psp"
        npriv = "priv" if (control_value & 0b01) == 0 else "unpriv"
        print("Control = %s, %s" % (spsel, npriv))

        cfsr_value = CM3.CFSR.read(self._target)
        print("      ┌─Divide by zero")
        print("      │┌─Unaligned memory access")
        print("      ││    ┌─No co-processor")
        print("      ││    │┌─Invalid PC on exception return")
        print("      ││    ││┌─Invalid state")
        print("      ││    │││┌─Undefined instruction")
        #     '10101010101010101010101010101010'
        print("{:>032b}".format(cfsr_value))
        #     '10101010101010101010101010101010'
        print(" BF still valid─┘  ││││││  ││ ││")
        print("       Stack error─┘│││││  ││ ││")
        print("      Unstack error─┘││││  ││ ││")
        print("     Imprecise error─┘│││  ││ ││")
        print("        Precise error─┘││  ││ ││")
        print(" Instruction bus error─┘│  ││ ││")
        print("                        │  ││ ││")
        print("        MMF still valid─┘  ││ ││")
        print("               Stack error─┘│ ││")
        print("              Unstack error─┘ ││")
        print("               Data Violation─┘│")
        print("         Instruction Violation─┘")

    def dump_stack(self, offset: int = 0):
        target = self._target

        cr_value = target.read_register("control")
        psp_selector = (cr_value & 0b10) != 0
        msp_value = target.read_register("msp")
        psp_value = target.read_register("psp")

        print("Values on msp stack%s:" % (" (currently selected)" if not psp_selector else ""))
        _print_stack_content(msp_value, offset, target)
        print("Values on psp stack%s:" % (" (currently selected)" if psp_selector else ""))
        _print_stack_content(psp_value, offset, target)

    def dump_nvic_info(self):
        target = self._target
        ictr_value = CM3.ICTR.read(target)
        # 16 internal (system) interrupts and an increment of 32 external interrupts
        max_vt_entries = CM3.AMOUNT_OF_EXCEPTIONS + 32 * (1 + ictr_value)
        target.log.info("Maximum number of interrupts = %d (0x%X)" % (max_vt_entries, max_vt_entries))

        prio_group_number = CM3.AIRCR.read_pri_group(target)
        target.log.info("The preemption-subriority split is set to %d" % prio_group_number)

        vt_address = CM3.VTOR.read(target)
        vt_entries: List[int] = target.read_memory(vt_address, 4, max_vt_entries)
        if type(vt_entries) is not list:
            raise Exception("Failed to correctly read vector table")

        shcsr_value = CM3.SHCSR.read(target)
        icsr_value = CM3.ICSR.read(target)

        interrupts = list()
        for i in range(max_vt_entries):
            vt_entry: int = vt_entries[i]
            current = Interrupt(i, vt_address, vt_entry)
            if i < 16:
                # System interrupt
                current = self.parse_system_interrupt(i, current, icsr_value, shcsr_value)
            else:
                # External interrupt
                current = self.parse_external_interrupt(i - 16, current)
            interrupts.append(current)

        pretty_print_interrupts(interrupts, prio_group_number)

    def parse_external_interrupt(self, index, interrupt):
        interrupt.name = "Interrupt %04d" % index
        interrupt.enabled = CM3.ExtIntSETENRegs.read_bit_n(self._target, index)
        interrupt.pended = CM3.ExtIntSETPENDRegs.read_bit_n(self._target, index)
        interrupt.active = CM3.ExtIntACTIVERegs.read_bit_n(self._target, index)
        interrupt.priority = CM3.ExtIntPRIORegs.read_field_n(self._target, index)
        return interrupt

    def parse_system_interrupt(self, index: int, interrupt: Interrupt, icsr_value: int, shcsr_value: int):
        interrupt.name = SYSTEM_INTERRUPTS[index]
        if index < 0 or index >= CM3.AMOUNT_OF_EXCEPTIONS:
            raise Exception("Not a system exception.")

        elif index in [0, 7, 8, 9, 10, 13]:
            pass

        elif index in [1, 2, 3]:
            interrupt.enabled = True
            interrupt.active = index == (CM3.ICSR.MASK_VECT_ACTIVE & icsr_value)
            interrupt.pended = (index == 2 and (CM3.ICSR.MASK_NMI_PEND_SET & icsr_value))
            interrupt.priority = index - 4

        else:
            # Field 0 of the SEPLR is the MMF (id 4)
            interrupt.priority = CM3.SEPLR.read_field_n(self._target, index - 4)

            if index == 4:
                interrupt.enabled = shcsr_value & CM3.SHCSR.MASK_MEM_FAULT_ENA != 0
                interrupt.pended = shcsr_value & CM3.SHCSR.MASK_MEM_FAULT_PENDING != 0
                interrupt.active = shcsr_value & CM3.SHCSR.MASK_MEM_FAULT_ACTIVE != 0

            elif index == 5:
                interrupt.enabled = shcsr_value & CM3.SHCSR.MASK_BUS_FAULT_ENA != 0
                interrupt.pended = shcsr_value & CM3.SHCSR.MASK_BUS_FAULT_PENDING != 0
                interrupt.active = shcsr_value & CM3.SHCSR.MASK_BUS_FAULT_ACTIVE != 0

            elif index == 6:
                interrupt.enabled = shcsr_value & CM3.SHCSR.MASK_USAGE_FAULT_ENA != 0
                interrupt.pended = shcsr_value & CM3.SHCSR.MASK_USAGE_FAULT_PENDING != 0
                interrupt.active = shcsr_value & CM3.SHCSR.MASK_USAGE_FAULT_ACTIVE != 0

            elif index == 11:
                interrupt.enabled = True
                interrupt.pended = shcsr_value & CM3.SHCSR.MASK_SV_CALL_PENDING != 0
                interrupt.pended = shcsr_value & CM3.SHCSR.MASK_SV_CALL_ACTIVE != 0

            elif index == 12:
                interrupt.enabled = True
                interrupt.pended = False
                interrupt.active = shcsr_value & CM3.SHCSR.MASK_MONITOR_ACTIVE != 0

            elif index == 14:
                interrupt.enabled = True
                interrupt.pended = icsr_value & CM3.ICSR.MASK_PEND_SV_SET != 0
                interrupt.active = shcsr_value & CM3.SHCSR.MASK_SV_PEND_ACTIVE != 0

            elif index == 15:
                interrupt.enabled = True
                interrupt.pended = icsr_value & CM3.ICSR.MASK_PEND_ST_SET != 0
                interrupt.active = shcsr_value & CM3.SHCSR.MASK_SYS_TICK_ACTIVE != 0

            else:
                raise Exception("Invalid state")

        return interrupt

    def dump_hard_fault(self):
        hfsr_value = CM3.HFSR.read(self._target)
        hf_forced = hfsr_value & CM3.HFSR.MASK_FORCED != 0
        hf_table = hfsr_value & CM3.HFSR.MASK_TABLE != 0

        print("Hard Fault was\n\tForced? %s\n\tTable? %s" % (hf_forced, hf_table))

    def dump_memory_fault(self):
        cfsr_value = CM3.CFSR.read(self._target)
        print("{:>032b}".format(cfsr_value))
        #     '00000000000000000000001101101100'
        print("        MMF still valid ┘  ││ ││")
        print("               Stack error ┘│ ││")
        print("              Unstack error ┘ ││")
        print("               Data Violation ┘│")
        print("         Instruction Violation ┘")

        mmfar_value = CM3.MMFAR.read(self._target)
        print("MMFAR: 0x%8X" % mmfar_value)


def load_plugin(avatar: Avatar, force: bool = False) -> None:
    if not force and avatar.arch != CM3:
        raise Exception("Wrong dump tool for this architecture. Ignore this by using the force flag.")
    target: Target
    for name, target in avatar.targets.items():
        if hasattr(target, 'pretty_dump'):
            raise Exception("A pretty dump utility is already connected")
        target.pretty_dump = CortexM3DumpTool(target)
