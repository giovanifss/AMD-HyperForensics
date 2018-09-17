import struct

class Paginator(object):
    def __init__(self, memory):
        self.memory = memory
        self.entry_size = 8

    def entry_present(self, entry):
        return entry & 0x1

    def page_size_flag(self, entry):
        return (entry & (1 << 7)) == (1 << 7)

#----------------------------------------------------------------
# 32 Bit Legacy Mode translation - from pdpt to physical address
#----------------------------------------------------------------
    def get_npt_pdpt(self, cr3):
        '''
        Extract the base address of the Page Directory Pointer Table from Nested Page Table Pointer (nptp).
        NPTP:
            - Bits 31:5 = Base Address of Page-Directory-Pointer-Table
            - Bits 4:3 = Writethrough and cache disble bits
            - Bits 2:0 = Reserved
        '''
        mask = 0xffffffe0
        return (cr3 & mask)

    def get_npt_pdpte(self, pdpt, vaddr):
        '''
        Get the Page-Directory-Pointer Table Entry (PDPTE) from PDPT
        GPA:
            - 31:30 = Page-Directory-Pointer Offset
        '''
        # Mask for PDPT Offset
        mask = 0xc0000000   # Bits 31:30
        pdpt_offset = ((vaddr & mask) >> 30) * self.entry_size
        pdpte_address = (pdpt | pdpt_offset)
        raw = self.memory.read_at_offset(pdpte_address, 8)
        return struct.unpack("<Q", raw)[0]

    def get_npt_pdt(self, pdpte):
        '''
        Get the Page Directory Table (PDT) Base Address from PDPT Entry
        PDPT Entry:
            - 51:12 = Page-Directory Table Base Address
            - 0     = Present Bit
        '''
        # Mask for PDT Base Address
        mask = 0xffffffffff000   # Bits 51:12
        if not self.entry_present(pdpte):   # If entry page is not present in memory
            return None
        return (pdpte & mask)

    def get_npt_pdte(self, pdt, vaddr):
        '''
        Get the Page Directory Table Entry (PDTE) from PDT
        GPA:
            - 29:21 = Page Directory Offset
        '''
        # Mask for PDT Offset
        #mask = 0x3fe00000   # Bits 29:21
        pdt_offset = ((vaddr >> 21) & 0x1ff) * self.entry_size
        pdte_address = (pdt | pdt_offset)                   # PDT 12 least significant bits are 0
        raw = self.memory.read_at_offset(pdte_address, 8)
        return struct.unpack("<Q", raw)[0]

    def get_npt_pt(self, pdte):
        '''
        Get the Page Table (PT) Base Address from PDT Entry
        PDT Entry:
            - 51:12 = Page-Table Base Address
            - 0     = Present Bit
        '''
        # Mask for PT Base Address
        mask = 0xffffffffff000   # Bits 51:12
        if not self.entry_present(pdte):    # If entry page is not present in memory
            return None
        return (pdte & mask)

    def get_npt_pte(self, pt, vaddr):
        '''
        Get the Page Table Entry (PTE) from PT
        GPA:
            - 20:12 = Page-Table Offset
        '''
        # Mask for PT Offset
        #mask = 0x1ff000     # Bits 20:12
        pt_offset = ((vaddr >> 12) & 0x1ff) * self.entry_size
        pte_address = (pt | pt_offset)                  # PT 12 least significant bits are 0
        raw = self.memory.read_at_offset(pte_address, 8)
        return struct.unpack("<q", raw)[0]

    def get_npt_phy(self, pte):
        '''
        Get the Physical Page (PHY) Base Address from PT Entry
        PT Entry:
            - 51:12 = Physical-Page Base Address
            - 0     = Present Bit
        '''
        # Mask for PHY Base Address
        mask = 0xffffffffff000   # Bits 51:12
        if not self.entry_present(pte):     # If entry page is not present in memory
            return None
        return (pte & mask)

    def get_npt_phye_addr(self, phy, vaddr):
        '''
        Get the Physical Page Entry (PHYE) from PHY
        GPA:
            - 11:0 = Physical-Page Offset
        '''
        # Mask for PHY Offset
        mask = 0xfff
        phy_offset = (vaddr & mask)
        phye_address = (phy | phy_offset)
        return phye_address
        #raw = self.memory.read_at_offset(phye_address, 8)
        #print "-------- PHY Entry: " + str(hex(struct.unpack("<Q", raw)[0]))
        #return struct.unpack("<Q", raw)[0]

    def get_npt_2mb_phy(self, pde, vaddr):
        '''
        Get the 2 MB Physical Page Base Address from PD Entry
        PD Entry:
            - 51:21 = 2 MB Physical-Page Base Address
        '''
        # Mask for 2MB PHY Base Address
        mask = 0xfffffffe00000  # Bits 51:21
        if not self.entry_present(pde):     # If entry page is not present in memory
            return None
        return (pde & mask)

    def get_npt_2mb_phye_addr(self, phy, vaddr):
        '''
        Get the 2 MB Physical Page Entry (2MBPHYE) from 2 MB PHY
        vaddr:
            - 20:0 = Physical page offset
        '''
        # Mask for 2MBPHYE offset
        mask = 0x1fffff
        phy_offset = (vaddr & mask)
        phye_address = (phy | phy_offset)
        return phye_address
        #raw = self.memory.read_at_offset(phye_address, 8)
        #print "-------- PHY Entry: " + str(hex(struct.unpack("<Q", raw)[0]))
        #return struct.unpack("<Q", raw)[0]

    def guest_vtop_npt(self, vaddr, cr3, nptp):
        '''
        Translate the Guest Virtual Address to Guest Physical Address through Nested Paging Table
        '''
        pdpt = self.get_npt_pdpt(cr3)
        if pdpt == None:
            return None

        phy_pdpt = self.vtop(pdpt, nptp)
        if phy_pdpt == None:
            return None

        pdpte = self.get_npt_pdpte(phy_pdpt, vaddr)
        if pdpte == None:
            return None

        print "----> Guest PDPT Addresses:\n\t---- Virtual: " + str(hex(pdpt)) + "\n\t---- Physical: " + str(hex(phy_pdpt)) + "\n\t---- Entry: " + str(hex(pdpte))

        pdt = self.get_npt_pdt(pdpte)
        if pdt == None:
            return None

        phy_pdt = self.vtop(pdt, nptp)
        if phy_pdt == None:
            return None

        pdte = self.get_npt_pdte(phy_pdt, vaddr)
        if pdte == None:
            return None

        print "----> Guest PDT Addresses:\n\t---- Virtual: " + str(hex(pdt)) + "\n\t---- Physical: " + str(hex(phy_pdt)) + "\n\t---- Entry: " + str(hex(pdte))

        if not self.page_size_flag(pdte):
            pt = self.get_npt_pt(pdte)
            if pt == None:
                return None

            phy_pt = self.vtop(pt, nptp)
            if phy_pt == None:
                return None

            pte = self.get_npt_pte(phy_pt, vaddr)
            if pte == None:
                return None

            print "----> Guest PT Addresses:\n\t---- Virtual: " + str(hex(pt)) + "\n\t---- Physical: " + str(hex(phy_pt)) + "\n\t---- Entry: " + str(hex(pte))

            phy = self.get_npt_phy(pte)
            if phy == None:
                return None
            return self.get_npt_phye_addr(phy, vaddr)  # Return phye
            #phy_phy = self.vtop(phy, nptp)
            #print "---> System Physical Address of PHY: " + str(hex(phy_phy))
            #if phy_phy == None:
            #    return None
            #return self.get_npt_phye_addr(phy_phy, vaddr)  # Return phye
        else:   # 2MB Page table
            phy = self.get_npt_2mb_phy(pdte, vaddr)
            if phy == None:
                return None
            return self.get_npt_2mb_phye_addr(phy, vaddr)
            #phy_phy = self.vtop(phy, nptp)
            #print "---> System Physical Address of 2MB PHY: " + str(hex(phy_phy))
            #if phy_phy == None:
            #    return None
            #return self.get_npt_2mb_phye_addr(phy_phy, vaddr)

#----------------------------------------------------------------
# 64 Bit Long Mode translation - from pml4 to physical address
#----------------------------------------------------------------
    def get_pml4(self, cr3):
        '''
        Extract the base address of the Page-Map Level 4 table (pml4) from Nested Page Table Pointer (nptp).
        NPTP:
            - Bits 63:52 = 0
            - Bits 51:12 = Base Address of PML4
            - Bits 11:5 = Reserved
            - Bits 4:3 = Writethrough and cache disble bits
            - Bits 2:0 = Reserved
        '''
        # Long Mode Paging
        # Mask for PML4 base address
        mask = 0xffffffffff000   # Bits 51:12
        return (cr3 & mask)

    def get_pml4e(self, pml4, vaddr):
        '''
        Get the Page-Map Level 4 Entry (PML4E) from PML4
        GPA:
            - 63:48 = Sign Extend
            - 47:39 = Page-Map Level 4 Offset
        '''
        # Mask for PML4 Offset
        mask = 0xff8000000000   # Bits 47:39
        #pml4_offset = (vaddr & mask) >> 39
        pml4_offset = (vaddr & mask) >> 36
        pml4e_address = pml4 | pml4_offset              # PML4 12 least significant bits are 0
        raw = self.memory.read_at_offset(pml4e_address, 8)
        return struct.unpack("<Q", raw)[0]

    def get_pdpt(self, pml4e):
        '''
        Get the Page-Directory-Pointer Table Base Address (PDPT) from PML4 Entry
        PML4 Entry:
            - 51:12 = Page-Directory-Pointer Table Base Address
            - 0     = Present Bit
        '''
        # Mask for PDPT Base Address
        mask = 0xffffffffff000   # Bits 51:12

        if not self.entry_present(pml4e):   # If entry page is not present in memory
            return None
        return (pml4e & mask)

    def get_pdpte(self, pdpt, vaddr):
        '''
        Get the Page-Directory-Pointer Table Entry (PDPTE) from PDPT
        GPA:
            - 38:30 = Page-Directory-Pointer Offset
        '''
        # Mask for PDPT Offset
        mask = 0x7fc0000000     # Bits 38:30
        #pdpt_offset = (vaddr & mask) >> 30
        pdpt_offset = (vaddr & mask) >> 27
        pdpte_address = (pdpt | pdpt_offset)            # PDPT 12 least significant bits are 0
        raw = self.memory.read_at_offset(pdpte_address, 8)
        return struct.unpack("<Q", raw)[0]

    def get_pdt(self, pdpte):
        '''
            Get the Page Directory Table (PDT) Base Address from PDPT Entry
            PDPT Entry:
                - 51:12 = Page-Directory Table Base Address
                - 0     = Present Bit
        '''
        # Mask for PDT Base Address
        mask = 0xffffffffff000   # Bits 51:12

        if not self.entry_present(pdpte):   # If entry page is not present in memory
            return None
        return (pdpte & mask)

    def get_pdte(self, pdt, vaddr):
        '''
        Get the Page Directory Table Entry (PDTE) from PDT
        GPA:
            - 29:21 = Page Directory Offset
        '''
        # Mask for PDT Offset
        mask = 0x3fe00000   # Bits 29:21
        #pdt_offset = (vaddr & mask) >> 21
        pdt_offset = ((vaddr >> 21) & 0x1ff) * self.entry_size
        pdte_address = (pdt | pdt_offset)               # PDT 12 least significant bits are 0
        raw = self.memory.read_at_offset(pdte_address, 8)
        return struct.unpack("<Q", raw)[0]

    def get_1gb_phy(self, pdpte):
        mask = 0xfffffc0000000
        if not self.entry_present(pdpte):
            return None
        return (pdpte & mask)

    def get_1gb_phye_addr(self, phy, vaddr):
        mask = 0x3fffffff
        phy_offset = (vaddr & mask)
        phye_address = (phy | phy_offset)
        return phye_address
        #raw = self.memory.read_at_offset(phye_address, 8)
        #return struct.unpack("<Q", raw)[0]

    def get_2mb_phy(self, pdte):
        mask = 0xfffffffe00000
        if not self.entry_present(pdte):
            return None
        return (pdte & mask)

    def get_2mb_phye_addr(self, phy, vaddr):
        mask = 0x00000001fffff
        phy_offset = (vaddr & mask)
        phye_address = (phy | phy_offset)
        return phye_address
        #raw = self.memory.read_at_offset(phye_address, 8)
        #return struct.unpack("<Q", raw)[0]

    def get_pt(self, pdte):
        '''
        Get the Page Table (PT) Base Address from PDT Entry
        PDT Entry:
            - 51:12 = Page-Table Base Address
            - 0     = Present Bit
        '''
        # Mask for PT Base Address
        mask = 0xffffffffff000   # Bits 51:12

        if not self.entry_present(pdte):    # If entry page is not present in memory
            return None
        return (pdte & mask)

    def get_pte(self, pt, vaddr):
        '''
        Get the Page Table Entry (PTE) from PT
        GPA:
            - 20:12 = Page-Table Offset
        '''
        # Mask for PT Offset
        mask = 0x1ff000     # Bits 20:12
        #pt_offset = (vaddr & mask) >> 12
        pt_offset = ((vaddr >> 12) & 0x1ff) * self.entry_size
        pte_address = (pt | pt_offset)                  # PT 12 least significant bits are 0
        raw = self.memory.read_at_offset(pte_address, 8)
        return struct.unpack("<Q", raw)[0]

    def get_phy(self, pte):
        '''
        Get the Physical Page (PHY) Base Address from PT Entry
        PT Entry:
            - 51:12 = Physical-Page Base Address
            - 0     = Present Bit
        '''
        # Mask for PHY Base Address
        mask = 0xffffffffff000   # Bits 51:12
        if not self.entry_present(pte):     # If entry page is not present in memory
            return None
        return (pte & mask)

    def get_phye_addr(self, phy, vaddr):
        '''
        Get the Physical Page Entry (PHYE) from PHY
        GPA:
            - 11:0 = Physical-Page Offset
        '''
        # Mask for PHY Offset
        mask = 0xfff
        #phy_offset = (vaddr & mask)
        phy_offset = (vaddr & ((1 << 12)  - 1))
        phye_address = (phy | phy_offset)
        return phye_address
        #raw = self.memory.read_at_offset(phye_address, 8)
        #return struct.unpack("<Q", raw)[0]

    def vtop(self, vaddr, cr3):
        '''
        Translate the Guest Physical Address to Host Physical Address through Nested Paging Table
        '''
        print "==> Translating Guest Physical Address: " + str(hex(vaddr)) + " to System Physical Address "
        pml4 = self.get_pml4(cr3)
        if pml4 == None:
            return None

        pml4e = self.get_pml4e(pml4, vaddr)
        if pml4e == None:
            return None

        pdpt = self.get_pdpt(pml4e)
        if pdpt == None:
            return None

        pdpte = self.get_pdpte(pdpt, vaddr)
        if pdpte == None:
            return None

        if self.page_size_flag(pdpte):
            phy = self.get_1gb_phy(pdpte)
            if phy == None:
                return None
            print "==> Translated to 1GB page at " + str(hex(self.get_1gb_phye_address(phy, vaddr)))
            return self.get_1gb_phye_address(phy, vaddr)

        pdt = self.get_pdt(pdpte)
        if pdt == None:
            return None

        pdte = self.get_pdte(pdt, vaddr)
        if pdte == None:
            return None

        if not self.page_size_flag(pdte):   # 4KB Page
            pt = self.get_pt(pdte)
            if pt == None:
                return None

            pte = self.get_pte(pt, vaddr)
            if pte == None:
                return None

            phy = self.get_phy(pte)
            if phy == None:
                return None
            print "==> Translated to 4KB page at " + str(hex(self.get_phye_addr(phy, vaddr)))
            return self.get_phye_addr(phy, vaddr)  # Return phye
        else:   # 2MB Page
            phy = self.get_2mb_phy(pdte)
            if phy == None:
                return None
            print "==> Translated to 2MB Page at " + str(hex(self.get_2mb_phye_addr(phy, vaddr)))
            return self.get_2mb_phye_addr(phy, vaddr)
