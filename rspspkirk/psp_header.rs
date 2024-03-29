#[repr(C, packed)]
pub struct Elf32Ehdr {
    e_magic: u32,
    e_class: u8,
    e_data: u8,
    e_idver: u8,
    e_pad: [u8; 9],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C, packed)]
pub struct Elf32Phdr {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

#[repr(C, packed)]
pub struct Elf32Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u32,
    sh_addr: u32,
    sh_offset: u32,
    sh_size: u32,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u32,
    sh_entsize: u32,
}

// Firmware 150 
#[repr(C, packed)]
struct PSPHeader2 {
    signature: u32,
    mod_info: PspModuleInfo,
    version: u8,
    nsegments: u8,
    elf_size: i32,
    psp_size: i32,
    entry: u32,
    modinfo_offset: u32,
    bss_size: i32,
    seg_align: [u16; 4],
    seg_address: [u32; 4],
    seg_size: [i32; 4],
    reserved: [u32; 5],
    devkitversion: u32,
    decrypt_mode: u32,
    key_data0: [u8; 0x30],
    comp_size: i32,
    unk_80: i32,
    reserved2: [i32; 2],
    key_data1: [u8; 0x10],
    tag: u32,
    scheck: [u8; 0x58],
    key_data2: u32,
    oe_tag: u32,
    key_data3: [u8; 0x1C],
}

//Unkn

// Total Length size of psp header
// [1 * 4] + 2 + 2 + 1 + 1 + 28 + 1 + 1 + 4 + 4 + 4 + 4 + 4 + [2 * 4] + [4 * 4] + [4 * 4] + 4 + 1 + 1

#[repr(C, packed)]
#[derive(Debug,Clone, Copy,PartialEq)]
pub struct PSPHeader {
    signature: [u8; 4],
    /// Value 1 SCE_MODULE_ATTR_CANT_STOP , SCE_MODULE_ATTR_LOAD, SCE_MODULE_ATTR_START
    mod_attribute: u16,
    //  Value 1 FLAG_COMPRESS , 2 FLAG_NORELOC (PFX NO RELOC , PRX RELOC)
    comp_attribute: u16,
    module_ver_lo: u8,
    module_ver_hi: u8,
    modname: [u8; 28],
    mod_version: u8,
    nsegments: u8,
    elf_size: u32,
    psp_size: u32,
    boot_entry: u32,
    modinfo_offset: u32,
    bss_size: u32,
    seg_align: [u16; 4],
    seg_address: [u32; 4],
    seg_size: [u32; 4],
    reserved: [u32; 5],
    devkit_version: u32,
    decrypt_mode: u8,
    padding: u8,
    overlap_size: u16,
    aes_key: [u8; 0x10],
    cmac_key: [u8; 0x10],
    cmac_header_hash: [u8; 0x10],
    comp_size: u32,
    unk_80: u32,
    unk_b8: u32,
    unk_bc: u32,
    cmac_data_hash: [u8; 0x10],
    tag: u32,
    scheck: [u8; 0x58],
    sha1_hash: [u8; 0x14],
    key_data4: [u8; 0x10],
}

//Maybe Latest
#[repr(C, packed)]
struct LPPSPHeader {
    signature: [u8; 4],
    mod_attribute: u16,
    comp_attribute: u16,
    module_ver_lo: u8,
    module_ver_hi: u8,
    modname: [u8; 28],
    mod_version: u8,
    nsegments: u8,
    elf_size: u32,
    psp_size: u32,
    boot_entry: u32,
    modinfo_offset: u32,
    bss_size: u32,
    seg_align: [u16; 4],
    seg_address: [u32; 4],
    seg_size: [u32; 4],
    reserved: [u32; 5],
    devkit_version: u32,
    decrypt_mode: u8,
    padding: u8,
    overlap_size: u16,
    aes_key: [u8; 0x10],
    cmac_key: [u8; 0x10],
    cmac_header_hash: [u8; 0x10],
    comp_size: u32,
    unk_80: u32,
    unk_b8: u32,
    unk_bc: u32,
    cmac_data_hash: [u8; 0x10],
    tag: u32,
    scheck: [u8; 0x58],
    sha1_hash: [u8; 0x14],
    key_data4: [u8; 0x10],
}

/// Attr Value PSPModuleInfo Elf (Binary) , PFX (No Relocate), PRX (Relocated Executable) from YAPSD 
#[repr(C, packed)]
#[derive(Debug,Clone, Copy,PartialEq)]
pub struct PspModuleInfo {
    attribute : u16,
    module_ver_lo: u8,
    module_ver_hi: u8,
    module_name : [char;28]
}
