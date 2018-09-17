import struct

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.debug as debug
import volatility.scan as scan
import volatility.commands as commands
import volatility.conf as conf
import volatility.plugins.hypervisors.vmcb as vmcb_offsets

from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

#--------------------------------------------------------------------------------------------------
# VMCB Control Area checks:
#   - VMRUN Intercept bit
#   - Guest ASID
#   - TLB_Control
#   - Event Injection Type
#--------------------------------------------------------------------------------------------------
class VMRUNInterceptCheck(scan.ScannerCheck):
    """
    VMRUN Intercept bit must always be set.
    If not causes a #VMEXIT with error code VMEXIT_INVALID.
    """
    
    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get general intercepts field values
        field_offset, field_size = vmcb_offsets.control_area["GENERAL_INTERCEPTS_2"]

        # Get the general intercepts at offset 0x10
        general_intercepts = struct.unpack("<I", self.address_space.read(offset + field_offset, field_size))[0]
        return (general_intercepts & 0b1)   # Check if least significant bit is set

    def skip(self, data, offset):
        return 4096

class GuestASIDCheck(scan.ScannerCheck):
    """
    The ASID for the guests must not be 0
    The value 0 is reserved for host
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get GUEST ASID field values
        field_offset, field_size = vmcb_offsets.control_area["GUEST_ASID"]

        # Get the GUEST ASID field value
        guest_asid = struct.unpack("<I", self.address_space.read(offset + field_offset, field_size))[0]
        return guest_asid & 0xFFFFFFFF

    def skip(self, data, offset):
        return 4096

class TLBControlCheck(scan.ScannerCheck):
    """
    TLB_CONTROL bits must be:
        0x00: Do Nothing
        0x01: Flush all TLB Entries
        0x03: Flush this guest's TLB entries
        0x07: Flush this guest's non-global TLB entries. 
    All other values are reserved.
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get the TLB CONTROL field values
        field_offset, field_size = vmcb_offsets.control_area["TLB_CONTROL"]

        # Get the TLB_CONTROL at offset 0x58 + 0x4
        tlb_control = struct.unpack("<B", self.address_space.read(offset + field_offset, field_size))[0]

        # An if condition for all possibilities to assure that no invalid value will be accepted
        if not tlb_control & 255:       # Assure that no other bit is set when testing for 0
            return True
        if not tlb_control ^ 0b1:       # 0x01
            return True
        if not tlb_control ^ 0b11:      # 0x03
            return True
        return not tlb_control ^ 0b111  # 0x07

    def skip(self, data, offset):
        return 4096

class EventInjectionTypeCheck(scan.ScannerCheck):
    """
    Event Injection Type bits must be 0, 2, 3 or 4.
    Type field = BITS 10:8
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get the EVENTINJ field values
        # Field_size ignored because only the first three bites of EVENTINJ are relevant
        field_offset, field_size = vmcb_offsets.control_area["EVENTINJ"]

        eventinj_raw = struct.unpack("<B", self.address_space.read(offset + field_offset, 0x1))[0]  # Reads only one byte
        eventinj_type = eventinj_raw & 0b111    # Get only the TYPE field (least three significant bits)

        # Assure that only valid values are accepted
        if not eventinj_type:   # Test possible value 0x0 -> Only true if eventinj_type = 0b000
            return True
        if not eventinj_type ^ 0b10:        # 2
            return True
        if not eventinj_type ^ 0b11:        # 3
            return True
        return not eventinj_type ^ 0b100    # 4

    def skip(self, data, offset):
        return 4096

#--------------------------------------------------------------------------------------------------
# VMCB State Save Area checks:
#   - CPL
#   - EFER Register
#   - CR4 Register
#   - CR3 Register
#   - CR0 Register
#   - DR7 Register
#   - DR6 Register
#   - RFLAGS Register
#--------------------------------------------------------------------------------------------------
class CPLCheck(scan.ScannerCheck):
    """
    CPL has only two valid possibilities:
        0: Guest in real-mode
        3: Guest in virtual-mode
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get CPL field values
        field_offset, field_size = vmcb_offsets.state_save_area["CPL"]
        cpl = struct.unpack("<B", self.address_space.read(offset + field_offset, field_size))[0]

        if not cpl & 255:       # Possible value 0
            return True
        return not cpl ^ 0b11   # Possible value 3

    def skip(self, data, offset):
        return 4096

class EFERCheck(scan.ScannerCheck):
    """
    EFER.SVME (BIT 12)  Must be 1 (otherwise #VMEXIT with error code VMEXIT_INVALID).
    EFER Bits 63:16     MBZ - Must be zero
    EFER Bits 7:1       RAZ - Rread as zero (NOT IMPLEMENTED)
    EFER Bit  9         MBZ - Must be zero
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get EFER field values
        field_offset, field_size = vmcb_offsets.state_save_area["EFER"]

        efer = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]
        # Check bit 12
        if not (efer & 0x1000):             # Mask equal to 0b1000000000000
            return False

        # Check bits from 63 to 16 that must be zero
        if (efer & 0xffffffffffff0000):     # Mask with bits 63:16 setted and 15:0 zero
            return False

        return not (efer & 0x200)           # Check bit 9

    def skip(self, data, offset):
        return 4096

class CR4Check(scan.ScannerCheck):
    """
    CR4 Bits 63:22      MBZ - Must be zero
    CR4 Bits 15:11      MBZ - Must be zero
    CR4 Bit  19         MBZ - Must be zero
    CR4 Bit  17         MBZ - Must be zero
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get CR4 field values
        field_offset, field_size = vmcb_offsets.state_save_area["CR4"]
        cr4 = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]

        # Check bits from 63 to 22 that must be zero
        if (cr4 & 0xffffffffffc00000):  # Mask with bits 63:22 setted
            return False

        # Check bits 15 to 11 that must be zero
        if (cr4 & 0xf800):              # Mask with bits 15:11 setted
            return False

        if (cr4 & 0x80000):             # Mask with bit 19 setted
            return False

        return not cr4 & 0x20000        # Mask with bit 17 setted

    def skip(self, data, offset):
        return 4096

class CR3Check(scan.ScannerCheck):
    """
    CR3 Bits 63:52      MBZ - Must be zero
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get CR3 field values
        field_offset, field_size = vmcb_offsets.state_save_area["CR3"]
        cr3 = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]

        # Check bits from 63 to 52 that must be zero
        return not (cr3 & 0xfff0000000000000)   # Mask with bits 63:52 setted

    def skip(self, data, offset):
        return 4096

class CR0Check(scan.ScannerCheck):
    """
    CR0 Bit  4          Must be set (Forced to 1 by the processor, software can not clean it)
    CR0 Bits 63:32      MBZ - Must be zero
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get CR0 field values
        field_offset, field_size = vmcb_offsets.state_save_area["CR0"]
        cr0 = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]

        # Check if bit 4 is set
        if not (cr0 & 0x10):    # Mask with 4th bit set = 0b10000
            return False

        if not cr0 & 0x40000000 and cr0 & 0x20000000:   # If CR0.CD is 0 and CR0.NW is set - INVALID VMCB
            return False
        
        return not (cr0 & 0xffffffff00000000)   # Mask with 32 most significant bits set

    def skip(self, data, offset):
        return 4096

class ConservativeDR7Check(scan.ScannerCheck):
    """
    DR7 Bits 63:32      MBZ - Must be zero
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get CR7 field values
        field_offset, field_size = vmcb_offsets.state_save_area["DR7"]
        dr7 = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]

        # Check bits 63 to 32 that must be zero
        return not (dr7 & 0xffffffff00000000)   # Mask with 32 most significant bits set

    def skip(self, data, offset):
        return 4096

class AgressiveDR7Check(scan.ScannerCheck):
    """
    DR7 Bit  10         Read as 1
    DR7 Bits 12:11      RAZ - Read as zero
    DR7 Bits 15:14      RAZ - Read as zero
    DR7 Bits 63:32      MBZ - Must be zero
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get DR7 field values
        field_offset, field_size = vmcb_offsets.state_save_area["DR7"]
        dr7 = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]

        # Check if bit 10 is set
        if not (dr7 & 0x400):   # Mask with 10th bit set
            return False

        if (dr7 & 0x1800) or (dr7 & 0xc000):    # Check if any of the bits 11, 12, 14 or 15 is 1
            return False

        # Check bits 63 to 32 that must be zero
        return not (dr7 & 0xffffffff00000000)   # Mask with 32 most significant bits set

    def skip(self, data, offset):
        return 4096

class ConservativeDR6Check(scan.ScannerCheck):
    """
    DR6 Bit  12         MBZ - Must be zero
    DR6 Bits 63:16      MBZ - Must be zero
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get the DR6 field values
        field_offset, field_size = vmcb_offsets.state_save_area["DR6"]
        dr6 = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]

        # Check if bit 12 is zero
        if (dr6 & 0x1000):      # Mask with 12th bit set
            return False

        # Check bits 63 to 32 that must be zero
        return not (dr6 & 0xffffffff00000000)   # Mask with bits 63:32 setted

    def skip(self, data, offset):
        return 4096


class AgressiveDR6Check(scan.ScannerCheck):
    """
    DR6 Bit  12         MBZ - Must be zero
    DR6 Bits 11:4       Read as 1
    DR6 Bits 63:16      MBZ - Must be zero
    DR6 Bits 31:16      Read as 1 (Conflicts with 63:16 ?? Needs tests)
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get DR6 field values
        field_offset, field_size = vmcb_offsets.state_save_area["DR6"]
        dr6 = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]

        # Check bits 11 to 4 that are read as 1
        if not (dr6 & 0xff0):   # Mask with bits 11:4 setted
            return False

        # Check if bit 12 is zero
        if (dr6 & 0x1000):      # Mask with 12th bit set
            return False

        # Check if bits 31 to 16 are setted
        if not (dr6 & 0xffff0000):
            return False

        # Check bits 63 to 32 that must be zero
        return not (dr6 & 0xffffffff00000000)   # Mask with bits 63:32 setted

    def skip(self, data, offset):
        return 4096

class RFLAGSCheck(scan.ScannerCheck):
    """
    RFLAGS Bits 63:22   Read as zero
    RFLAGS Bit  15      Read as zero
    RFLAGS Bit  5       Read as zero
    RFLAGS Bit  3       Read as zero
    RFLAGS Bit  1       Read as one
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get RFLAGS field values
        field_offset, field_size = vmcb_offsets.state_save_area["RFLAGS"]
        rflags = struct.unpack("<Q", self.address_space.read(offset + field_offset, field_size))[0]

        if (rflags & 0xffffffffffc00000):   # Mask with bits 63:22 setted
            return False

        # Masks with:
        #   - bit 15 setted
        #   - bit 5 setted
        #   - bit 3 setted
        if (rflags & 0x8000) or (rflags & 0x20) or (rflags & 0x8):
            return False

        return rflags & 0x2     # Mask with bit 1 setted

    def skip(self, data, offset):
        return 4096

#--------------------------------------------------------------------------------------------------
# VMCB Consistency Checks
#   - Reproduce the consistency checks performed by AMD to verify if the VMCB is invalid
#--------------------------------------------------------------------------------------------------
class VMCBConsistencyCheck(scan.ScannerCheck):
    """
    1) If Long mode and paging are enabled, segment protection must be enabled too
    EFER.LME and CR0.PG are both set, CR0.PE must not be 0

    2) If long mode and paging are enabled, physical address extension must be enabled too
    EFER.LME and CRO.PG are both set, CR4.PAE must not be 0

    3) (NOT IMPLEMENTED) Long Mode, paging, physical address extension, code segment long mode, code segment default operand size
    can not be set at the same time. (NOT IMPLEMENTED)
    """

    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        # Get least significant half of CR0
        cr0 = struct.unpack("<I", self.address_space.read(offset + vmcb_offsets.state_save_area["CR0"][0], 0x4))[0]
        # Get second least significant byte of EFER
        efer = struct.unpack("<B", self.address_space.read(offset + vmcb_offsets.state_save_area["EFER"][0] + 0x1, 0x1))[0]
        # Get least significant byte of CR4
        cr4 = struct.unpack("<B", self.address_space.read(offset + vmcb_offsets.state_save_area["CR4"][0], 0x1))[0]

        lme_mask    = 0x01
        pg_mask     = 0x80000000
        pe_mask     = 0x01
        pae_mask    = 0x20

        if (efer & lme_mask and cr0 & pg_mask and not cr0 & pe_mask):   # Check number 1
            return False

        return not (efer & lme_mask and cr0 & pg_mask and not cr4 & pae_mask)   # Check number 2

    def skip(self, data, offset):
        return 4096

#--------------------------------------------------------------------------------------------------
# Conservative VMCB scan, perform only checks that must have at least one bit set:
#   - VMRUN Intercept Check
#   - TLB Control Check
#   - Event Injection Type Check
#   - EFER Check
#   - CPL Check
#   - CR0 Check
#--------------------------------------------------------------------------------------------------
class ConservativeVMCBScan(scan.BaseScanner):
    """
    This Scanner finds possible VMCB candidates testing only immutable fields
    """
    checks = [  ("VMRUNInterceptCheck", {}),
                ("GuestASIDCheck", {}),
                ("TLBControlCheck", {}),
                ("EventInjectionTypeCheck", {}),
                ("EFERCheck", {}),
                ("CPLCheck", {}),
                ("CR0Check", {}),
                ("ConservativeDR7Check", {}),
                ("ConservativeDR6Check", {}),
                ("VMCBConsistencyCheck", {})
             ]

#--------------------------------------------------------------------------------------------------
# Agressive VMCB scan, checks all static values:
#   - VMRUN Intercept Check
#   - Guest ASID Check
#   - TLBControlCheck
#   - Event Injection Type Check
#   - CPL Check
#   - EFER Check
#   - CR4 Check
#   - CR3 Check
#   - CR0 Check
#   - DR7 Check
#   - DR6 Check
#   - RFLAGS Check
#   - Long Mode Paging Segment Protection Disabled Check
#   - Long Mode Paging PAE Disabled Check
#--------------------------------------------------------------------------------------------------
class AgressiveVMCBScan(scan.BaseScanner):
    """
    This Scanner finds possible VMCB candidates testing fields that 'SHOULD' not be changed by hypervisor
    """
    checks = [  ("VMRUNInterceptCheck", {}),
                ("GuestASIDCheck", {}),
                ("TLBControlCheck", {}),
                ("EventInjectionTypeCheck", {}),
                ("EFERCheck", {}),
                ("CPLCheck", {}),
                ("CR0Check", {}),
                ("CR4Check", {}),
                ("CR3Check", {}),
                ("AgressiveDR7Check", {}),
                ("AgressiveDR6Check", {}),
                ("RFLAGSCheck", {}),
                ("VMCBConsistencyCheck", {})
             ]
#--------------------------------------------------------------------------------------------------
# The plugin class contains the following aditional (custom) atributes:
#   - addr_space = The address space loaded
#       * Used to keep address space available in render_text and get_vmcb_field
#--------------------------------------------------------------------------------------------------
class AMDHyperLs(commands.Command):
    '''
    Detect hypervisors using AMD-V a.k.a. SVM technology.
    '''
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        self._config.add_option('VERBOSE', short_option = 'v', default = False, action = 'store_true',
                help = 'Enable verbose output')
        self._config.add_option('AGRESSIVE', short_option = 'a', default = False, action = 'store_true',
                help = 'Activate agressive search: Check fields that \'SHOULD\' not be changed by hypervisors\nNOTE: Malicious hypervisors can temper those fields to avoid this tool, but for normal cases, this scan will produce better results')

    def unified_output(self, data):
        """
        This standardizes the output formatting
        """
        return TreeGrid([("Offset", Address)], self.generator(data))

    def render_text(self, outfd, data):
        """
        Override render_text to print VMCB structure
        """
        if not data:
            outfd.write(":: No VMCBs found\n")
            return

        if self._config.VERBOSE:
            outfd.write(":: Describing found VMCBs...\n")

        for address in data:
            if self._config.VERBOSE:
                outfd.write("|_ VMCB at {0:#0{1}x}\n".format(address, 18))

                outfd.write("\t|_ Control Area Values:\n")
                for field in sorted(vmcb_offsets.control_area):
                    outfd.write(self.get_field_string(address, field, vmcb_offsets.control_area))

                outfd.write("\t|_ Control State Save Area Values:\n")
                for field in sorted(vmcb_offsets.state_save_area):
                    outfd.write(self.get_field_string(address, field, vmcb_offsets.state_save_area))

    # Used in render_text to clean code
    def get_field_string(self, vmcb_address, field, vmcb_area):
        field_offset, field_size = vmcb_area[field]
        field_string = "\t\t|_ {}".format(field)

        if len(field) > 20:
            field_string += "\t"
        elif len(field) > 12:
            field_string += "\t" * 2
        elif len(field) > 4:
            field_string += "\t" * 3
        else:
            field_string += "\t" * 4

        hex_pad = field_size * 2 + 2
        field_string += "=>\t{0:#0{1}x}\n".format(self.get_vmcb_field(vmcb_address, field_offset, field_size), hex_pad)

        return field_string

    def generator(self, data):
        """
        This yields data according to the unified output format
        """
        for offset in data:
            yield (0, [Address(offset)])

    def calculate(self):
        self.addr_space = utils.load_as(self._config, astype = 'physical')
        vmcbs_found = []
        debug.debug("DEBUG MODE")

        vmcb_scan = None
        if self._config.AGRESSIVE:
            debug.info("Starting agressive search...")
            vmcb_scan = AgressiveVMCBScan()
        else:
            debug.info("Starting conservative search...")
            vmcb_scan = ConservativeVMCBScan()

        for offset in vmcb_scan.scan(self.addr_space):
            debug.info(">> Possible VMCB at 0x%x" % offset)
            vmcbs_found.append(offset)

        return vmcbs_found

    def get_vmcb_field(self, address, offset, size):
        raw = self.addr_space.read(address + offset, size)
        if size == 1:
            return struct.unpack('<B', raw)[0]
        elif size == 2:
            return struct.unpack('<H', raw)[0]
        elif size == 4:
            return struct.unpack('<I', raw)[0]
        elif size == 8:
            return struct.unpack('<Q', raw)[0]
        else:
            return None
