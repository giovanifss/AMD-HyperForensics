#--------------------------------------------------------------------------------------------------
# VMCB structure fields information
#
# Structure:
#   "FIELD_NAME" = (offset, size)
#       * size = Bytes occupied in memory
#--------------------------------------------------------------------------------------------------

control_area = {
    "CR15_INTERCEPT"                : (0x000, 0x04),
    "DR0_INTERCEPT"                 : (0x004, 0x04),
    "INTERCEPT_EXCEPTION_VECTORS"   : (0x008, 0x04),
    "GENERAL_INTERCEPTS_1"          : (0x00C, 0x04),
    "GENERAL_INTERCEPTS_2"          : (0x010, 0x04),
    "IOPM_BASE_PA"                  : (0x040, 0x08),
    "MSRPM_BASE_PA"                 : (0x048, 0x08),
    "TSC_OFFSET"                    : (0x050, 0x08),
    "GUEST_ASID"                    : (0x058, 0x04),
    "TLB_CONTROL"                   : (0x05C, 0x01),
    "INTERRUPT_SHADOW"              : (0x068, 0x01),
    "EXITCODE"                      : (0x070, 0x08),
    "EXITINFO_1"                    : (0x078, 0x08),
    "EXITINFO_2"                    : (0x080, 0x08),
    "EXITINTINFO"                   : (0x088, 0x08),
    "NP_ENABLE"                     : (0x090, 0x01),
    "AVIC_APIC_BAR"                 : (0x098, 0x08),
    "PHY_GHCB"                      : (0x0A0, 0x08),
    "EVENTINJ"                      : (0x0A8, 0x08),
    "N_CR3"                         : (0x0B0, 0x08),
    "LBR_VIRTUALIZATION_ENABLE"     : (0x0B8, 0x01),
    "VMCB_CLEAN_BITS"               : (0x0C0, 0x08),
    "nRIP"                          : (0x0C8, 0x08),
    "AVIC_APIC_BACKING_PAGE"        : (0x0E0, 0x08),
    "AVIC_LOGICAL_TABLE"            : (0x0F0, 0x08),
    "AVIC_PHYSICAL_TABLE"           : (0x0F8, 0x08),
    "VMCB_SAVE_STATE_POINTER"       : (0x108, 0x08)
}

state_save_area = {
    "CPL"                           : (0x4CB, 0x01),
    "EFER"                          : (0x4D0, 0x08),
    "CR4"                           : (0x548, 0x08),
    "CR3"                           : (0x550, 0x08),
    "CR0"                           : (0x558, 0x08),
    "DR7"                           : (0x560, 0x08),
    "DR6"                           : (0x568, 0x08),
    "RFLAGS"                        : (0x570, 0x08),
    "RIP"                           : (0x578, 0x08),
    "RSP"                           : (0x5D8, 0x08),
    "RAX"                           : (0x5F8, 0x08),
    "STAR"                          : (0x600, 0x08),
    "LSTAR"                         : (0x608, 0x08),
    "CSTAR"                         : (0x610, 0x08),
    "SFMASK"                        : (0x618, 0x08),
    "KERNELGSBASE"                  : (0x620, 0x08),
    "SYSENTER_CS"                   : (0x628, 0x08),
    "SYSENTER_ESP"                  : (0x630, 0x08),
    "SYSENTER_EIP"                  : (0x638, 0x08),
    "CR2"                           : (0x640, 0x08),
    "G_PAT"                         : (0x668, 0x08),
    "DBGCTL"                        : (0x670, 0x08),
    "BR_FROM"                       : (0x678, 0x08),
    "BR_TO"                         : (0x680, 0x08),
    "LASTEXCPFROM"                  : (0x688, 0x08),
    "LASTEXCPTO"                    : (0x690, 0x08)
}
