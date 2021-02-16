# from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN
import math
from typing import Union

from capstone import *
from keystone.keystone_const import *
from unicorn import *
from unicorn.arm_const import *
from .architecture import Architecture
import avatar2

from avatar2.installer.config import QEMU, PANDA, OPENOCD, GDB_MULTI

class ARM(Architecture):

    get_qemu_executable = Architecture.resolve(QEMU)
    get_panda_executable = Architecture.resolve(PANDA)
    get_gdb_executable  = Architecture.resolve(GDB_MULTI)
    get_oocd_executable = Architecture.resolve(OPENOCD)



    qemu_name = 'arm'
    gdb_name = 'arm'
    registers = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4, 'r5': 5, 'r6': 6,
                 'r7': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11, 'r12': 12,
                 'sp': 13, 'lr': 14, 'pc': 15, 'cpsr': 25,
                 }
    unicorn_registers = {'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1, 'r2': UC_ARM_REG_R2,
                         'r3': UC_ARM_REG_R3, 'r4': UC_ARM_REG_R4, 'r5': UC_ARM_REG_R5,
                         'r6': UC_ARM_REG_R6, 'r7': UC_ARM_REG_R7, 'r8': UC_ARM_REG_R8,
                         'r9': UC_ARM_REG_R9, 'r10': UC_ARM_REG_R10, 'r11': UC_ARM_REG_R11,
                         'r12': UC_ARM_REG_R12, 'sp': UC_ARM_REG_SP, 'lr': UC_ARM_REG_LR,
                         'pc': UC_ARM_REG_PC, 'cpsr': UC_ARM_REG_CPSR}
    pc_name = 'pc'
    sr_name = 'cpsr'
    unemulated_instructions = ['mcr', 'mrc']
    capstone_arch = CS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN
    keystone_arch = KS_ARCH_ARM
    keystone_mode = KS_MODE_ARM
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_ARM

class ARM_CORTEX_M3(ARM):
    cpu_model = 'cortex-m3'
    qemu_name = 'arm'
    gdb_name = 'arm'

    capstone_arch = CS_ARCH_ARM
    keystone_arch = KS_ARCH_ARM
    capstone_mode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB | CS_MODE_MCLASS
    keystone_mode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB
    unicorn_arch = UC_ARCH_ARM
    unicorn_mode = UC_MODE_LITTLE_ENDIAN | UC_MODE_THUMB
    sr_name = 'xpsr'

    AMOUNT_OF_EXCEPTIONS = 16
    PERIPHERALS_START = 0xE0000000
    PERIPHERALS_END = 0xE0100000

    class _MmioRegister:
        """Offer basic functionality to easily .read or .write a memory mapped register"""

        @classmethod
        def read(cls, target, size=4, num_words=1) -> int:
            if hasattr(cls, 'ADDRESS'):
                return target.read_memory(cls.ADDRESS, size, num_words=num_words)
            else:
                raise NotImplementedError("Class does not have an ADDRESS")

        @classmethod
        def write(cls, target, value, size=4, num_words=1) -> int:
            if hasattr(cls, 'ADDRESS'):
                return target.write_memory(cls.ADDRESS, size, value=value, num_words=num_words)
            else:
                raise NotImplementedError("Class does not have an ADDRESS")

        @classmethod
        def set_bit(cls, target, bit_index, value):
            og_value = cls.read(target)

            if value == 0:
                cls.write(target, og_value & ~(1 << bit_index))
            elif value == 1:
                cls.write(target, og_value | 1 << bit_index)


    class _MultiBitMmioRegister(_MmioRegister):
        """Allow for bitwise-indexed access to registers that span multiple words"""

        @classmethod
        def read_bit_n(cls, target, n: int) -> bool:
            if hasattr(cls, 'ADDRESS') and hasattr(cls, 'END_ADDRESS'):
                base = n // 8 + cls.ADDRESS
                if base > cls.END_ADDRESS:
                    raise IndexError("Index out of range")
                byte_value = target.read_memory(base, 1)
                mask = 1 << (n % 8)
                return (byte_value & mask) > 0
            else:
                raise NotImplementedError("Class does not have an ADDRESS")

        @classmethod
        def write_bit_n(cls, target, n: int, value: bool):
            if hasattr(cls, 'ADDRESS') and hasattr(cls, 'END_ADDRESS'):
                base = n // 8 + cls.ADDRESS
                if base > cls.END_ADDRESS:
                    raise IndexError("Index out of range")
                byte_value = target.read_memory(base, 1)
                target_bit_mask = 1 << (n % 8)
                if value:
                    byte_value |= target_bit_mask
                else:
                    byte_value &= ~target_bit_mask
                target.write_memory(base, 1, byte_value)
            else:
                raise NotImplementedError("Class does not have an ADDRESS")

    class _MultiByteMmioRegister(_MmioRegister):
        @classmethod
        def read_field_n(cls, target, n: int) -> int:
            if hasattr(cls, 'ADDRESS') and hasattr(cls, 'END_ADDRESS') and hasattr(cls, 'FIELD_WIDTH'):
                base = cls.ADDRESS + n * cls.FIELD_WIDTH
                if base > cls.END_ADDRESS:
                    raise IndexError("Index out of range")
                value = target.read_memory(base, cls.FIELD_WIDTH)
                return value
            else:
                raise NotImplementedError("Class does not have an ADDRESS")

        @classmethod
        def write_field_n(cls, target, n: int, value):
            if hasattr(cls, 'ADDRESS') and hasattr(cls, 'END_ADDRESS') and hasattr(cls, 'FIELD_WIDTH'):
                base = cls.ADDRESS + n * cls.FIELD_WIDTH
                if base > cls.END_ADDRESS:
                    raise IndexError("Index out of range")
                target.write_memory(base, cls.FIELD_WIDTH, value)
            else:
                raise NotImplementedError("Class does not have an ADDRESS")

    class ICTR(_MmioRegister):
        """Interrupt Controller Type Register"""
        ADDRESS = 0xE000E004

        MASK_INT_LINES_NUM = 0xF

        @classmethod
        def read_interrupts(cls, target):
            return 32 * (1 + (cls.MASK_INT_LINES_NUM & cls.read(target)))

    class ExtIntSETENRegs(_MultiBitMmioRegister):
        ADDRESS = 0XE000E100
        END_ADDRESS = 0xE000E11C

    class ExtIntCLRENRegs(_MultiBitMmioRegister):
        ADDRESS = 0xE000E180
        END_ADDRESS = 0xE000E19C

    class ExtIntSETPENDRegs(_MultiBitMmioRegister):
        ADDRESS = 0XE000E200
        END_ADDRESS = 0xE000E21C

    class ExtIntCLRPENDRegs(_MultiBitMmioRegister):
        ADDRESS = 0xE000E280
        END_ADDRESS = 0xE000E29C

    class ExtIntACTIVERegs(_MultiBitMmioRegister):
        ADDRESS = 0xE000E300
        END_ADDRESS = 0xE000E31C

    class ExtIntPRIORegs(_MultiByteMmioRegister):
        ADDRESS = 0xE000E400
        END_ADDRESS = 0xE000E4EF
        FIELD_WIDTH = 1

    class SEPLR(_MultiByteMmioRegister):
        ADDRESS = 0xE000ED18
        END_ADDRESS = 0xE000ED23
        FIELD_WIDTH = 1

    class ICSR(_MmioRegister):
        """Interrupt Control and State Register"""
        ADDRESS = 0xE000ED04

        MASK_NMI_PEND_SET = 1 << 31

        MASK_PEND_SV_SET = 1 << 28
        MASK_PEND_SV_CLR = 1 << 27
        MASK_PEND_ST_SET = 1 << 26
        MASK_PEND_ST_CLR = 1 << 25

        MASK_ISR_PREEMPT = 1 << 23

        MASK_ISR_PENDING = 1 << 22
        SHIFT_VECT_PENDING = 12
        MASK_VECT_PENDING = 0b1111111111 << SHIFT_VECT_PENDING
        MASK_RET_TO_BASE = 1 << 11
        MASK_VECT_ACTIVE = 0b1111111111

        @classmethod
        def read_active_vector(cls, target):
            return cls.read(target) & cls.MASK_VECT_ACTIVE

        @classmethod
        def read_pending_vector(cls, target):
            return (cls.read(target) & cls.MASK_VECT_PENDING) >> cls.SHIFT_VECT_PENDING

    class VTOR(_MmioRegister):
        """Vector Table Offset Register"""
        ADDRESS = 0xE000ED08

        MASK_BASE = 0x01 << 29
        MASK_OFFSET = 0x1FFFFF80

    class AIRCR(_MmioRegister):
        """Application Interrupt and Reset Control Register"""
        ADDRESS = 0xE000ED0C

        SHIFT_VECT_KEY = 16
        MASK_VECT_KEY = 0b1111111111111111 << SHIFT_VECT_KEY

        MASK_ENDIANESS = 1 << 15

        SHIFT_PRI_GROUP = 8
        MASK_PRI_GROUP = 0b111 << SHIFT_PRI_GROUP

        MASK_SYS_RESET_REQ = 1 << 2
        MASK_VECT_CLR_ACTIVE = 1 << 1
        MASK_VECT_RESET = 1 << 0

        @classmethod
        def read_pri_group(cls, target):
            return (cls.read(target) & cls.MASK_PRI_GROUP) >> cls.SHIFT_PRI_GROUP

    class SHCSR(_MmioRegister):
        """System Handler Control and State Register"""
        ADDRESS = 0xE000ED24

        MASK_USAGE_FAULT_ENA = 1 << 18
        MASK_BUS_FAULT_ENA = 1 << 17
        MASK_MEM_FAULT_ENA = 1 << 16

        MASK_SV_CALL_PENDING = 1 << 15
        MASK_BUS_FAULT_PENDING = 1 << 14
        MASK_MEM_FAULT_PENDING = 1 << 13
        MASK_USAGE_FAULT_PENDING = 1 << 12
        MASK_SYS_TICK_ACTIVE = 1 << 11
        MASK_SV_PEND_ACTIVE = 1 << 10
        MASK_MONITOR_ACTIVE = 1 << 8
        MASK_SV_CALL_ACTIVE = 1 << 7
        MASK_USAGE_FAULT_ACTIVE = 1 << 3
        MASK_BUS_FAULT_ACTIVE = 1 << 1
        MASK_MEM_FAULT_ACTIVE = 1 << 0

    class CFSR(_MmioRegister):
        """Configurable Fault Status Register"""
        ADDRESS = 0xE000ED28

        MASK_DIV_ZERO = 1 << 25
        MASK_UNALIGNED = 1 << 24
        MASK_NO_CO_PROCESSOR = 1 << 19
        MASK_INVALID_PC_LOAD = 1 << 18
        MASK_INVALID_STATE = 1 << 17
        MASK_UNDEFINED_INST = 1 << 16
        MASK_BF_ADDR_STILL_VALID = 1 << 15
        MASK_BF_STACK_ERR = 1 << 12
        MASK_BF_UNSTACK_ERR = 1 << 11
        MASK_BF_IMPRECISE_ERR = 1 << 10
        MASK_BF_PRECISE_ERR = 1 << 9
        MASK_INST_BUS_ERR = 1 << 8
        MASK_MMF_ADDR_STILL_VALID = 1 << 7
        MASK_MMF_STACK_ERR = 1 << 4
        MASK_MMF_UNSTACK_ERR = 1 << 3
        MASK_DATA_VIOLATION = 1 << 1
        MASK_INST_VIOLATION = 1 << 0

    class HFSR(_MmioRegister):
        """Hard Fault Status Register"""
        ADDRESS = 0xE000ED2C

        MASK_FORCED = 0x01 << 30
        MASK_TABLE = 0x01 << 1

    class MMFAR(_MmioRegister):
        """Memory Management Fault Address Register"""
        ADDRESS = 0xE000ED34

        MASK_FAULT_ADDRESS = 0xFFFFFFFF

    class BFAR(_MmioRegister):
        """Bus Fault Address Register"""
        ADDRESS = 0xE000ED38

        MASK_FAULT_ADDRESS = 0xFFFFFFFF

    class MpuTR(_MmioRegister):
        """MPU Type Register"""
        ADDRESS = 0xE000ED90

        SHIFT_IREGION = 16
        MASK_IREGION = 0xFF << SHIFT_IREGION
        SHIFT_DREGION = 8
        MASK_DREGION = 0xFF << SHIFT_DREGION

        @classmethod
        def read_iregion(cls, tr_value):
            print("Cortex M3 always uses #dregion unified regions")
            return (tr_value & cls.MASK_IREGION) >> cls.SHIFT_IREGION

        @classmethod
        def parse_dregion(cls, tr_value):
            return (tr_value & cls.MASK_DREGION) >> cls.SHIFT_DREGION

    class MpuCR(_MmioRegister):
        ADDRESS = 0xE000ED94

        MASK_PRIV_DEF_ENA = 1 << 2
        MASK_HF_NMI_END = 1 << 1
        MASK_ENABLE = 1 << 0

    class MpuRNR(_MmioRegister):
        ADDRESS = 0xE000ED98

        MASK_REGION_NUMBER = 0xFF

    class MpuRBAR(_MmioRegister):
        ADDRESS = 0xE000ED9C

        MASK_ADDR = 0xFFFFFFE0
        MASK_VALID = 1 << 4
        MASK_REGION_NUMBER = 0xF

        @classmethod
        def write_advanced(cls, target, address: int, region_number: Union[int, None] = None):
            address_part = address & cls.MASK_ADDR
            if region_number is None:
                value = address_part
            else:
                region_number_part = region_number & cls.MASK_REGION_NUMBER
                value = address_part | cls.MASK_VALID
            cls.write(target, value, size=4, num_words=1)

    class MpuRASR(_MmioRegister):
        ADDRESS = 0xE000EDA0

        MASK_XN = 1 << 28

        SHIFT_AP = 24
        MASK_AP = 0b111 << SHIFT_AP

        SHIFT_TEX = 19
        MASK_TEX = 0b111 << SHIFT_TEX

        MASK_S = 1 << 18
        MASK_C = 1 << 17
        MASK_B = 1 << 16

        SHIFT_SRD = 8
        MASK_SRD = 0xFF << SHIFT_SRD

        SHIFT_SIZE = 1
        MASK_SIZE = 0b11111 << SHIFT_SIZE

        MASK_ENABLE = 1 << 0

        @staticmethod
        def calculate_size_value(size: int) -> int:
            next_power = 1 << (size - 1).bit_length()
            return int(math.log2(next_power)) - 1

        @staticmethod
        def calculate_access_permission(priv_read: bool, priv_write: bool, user_read: bool, user_write: bool, ) -> int:
            """Determines the correct AP field value for a combination of access"""

            priv_rw = priv_read and priv_write
            priv_ro = priv_read and not priv_write
            priv_wo = not priv_read and priv_write
            priv_na = not priv_read and not priv_write

            user_rw = user_read and user_write
            user_ro = user_read and not user_write
            user_wo = not user_read and user_write
            user_na = not user_read and not user_write

            if priv_wo or user_wo:
                raise AssertionError("Write-only regions are not allowed.")

            if priv_na and user_na:
                return 0b000

            if priv_rw and user_na:
                return 0b001

            if priv_rw and user_ro:
                return 0b010

            if priv_rw and user_rw:
                return 0b011

            if priv_ro and user_na:
                return 0b101

            if priv_ro and user_ro:
                return 0b110

            raise AssertionError("Combination of privileges is not supported.")

        @classmethod
        def write_advanced(cls, target, xn: bool = False, ap: int = 0, tex: int = 0, s: bool = False, c: bool = False,
                           b: bool = False, srd: int = 0, size: int = 0, enable: bool = False):
            """
            xn:     Execution access disable. True = Disallow
            ap:     Data access permission. Refer to .calculate_access_permission(bool,bool,bool,bool)
            tex:    Type Extension field.
            s:      Shareable
            c:      Cacheable
            b:      Bufferable
            srd:    Subregion disable. 8-bits, each bit disables 1/8th of the region when set.
            size:   Region size index. Refer to .calculate_size_value(int)
            enable: Disable or enable this region altogether
            """

            value = 0
            if xn:
                value |= cls.MASK_XN
            if s:
                value |= cls.MASK_S
            if c:
                value |= cls.MASK_C
            if b:
                value |= cls.MASK_B
            if enable:
                value |= cls.MASK_ENABLE

            if ap < 0 or ap > cls.MASK_AP:
                raise AssertionError("Value for AP out of bounds")
            value |= ap << cls.SHIFT_AP

            if tex < 0 or tex > cls.MASK_TEX:
                raise AssertionError("Value for TEX out of bounds")
            value |= tex << cls.SHIFT_TEX

            if srd < 0 or srd > cls.MASK_SRD:
                raise AssertionError("Value for SRD out of bounds")
            value |= srd << cls.SHIFT_SRD

            if size < 0 or size > cls.MASK_SIZE:
                raise AssertionError("Value for size out of bounds")
            value |= size << cls.SHIFT_SIZE

            cls.write(target, value)

    @staticmethod
    def register_write_cb(avatar, *args, **kwargs):

        if isinstance(kwargs['watched_target'],
                      avatar2.targets.qemu_target.QemuTarget):
            qemu = kwargs['watched_target']

            # xcps/cpsr encodes the thumbbit diffently accross different
            # ISA versions. Panda_target does not cleanly support cortex-m yet,
            # and hence uses the thumbbit as stored on other ARM versions.
            if isinstance(qemu, avatar2.targets.panda_target.PandaTarget):
                shiftval = 5
            else:
                shiftval = 24

            if args[0] == 'pc' or args[0] == 'cpsr':
                cpsr = qemu.read_register('cpsr')
                if cpsr & 1<< shiftval:
                    return
                else:
                    cpsr |= 1<<shiftval
                    qemu.write_register('cpsr', cpsr)

    @staticmethod
    def init(avatar):
        avatar.watchmen.add('TargetRegisterWrite', 'after',
                            ARM_CORTEX_M3.register_write_cb)

        pass
ARMV7M = ARM_CORTEX_M3


class ARMBE(ARM):
    qemu_name = 'armeb'
    capstone_mode = CS_MODE_BIG_ENDIAN
