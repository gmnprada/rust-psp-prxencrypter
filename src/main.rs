/// The Main Program of RsPrxEncrypter

extern crate rspspkirk;
use rspspkirk::psp_header::PSPHeader;
use rspspkirk::kirk_engine::{kirk_decrypt_key, kirk_cmd0,kirk_cmd15,kirk_forge};
use rspspkirk::psp_header::PspModuleInfo;
use clap::Parser;
use core::panic;
use std::fs::File;
use std::io::{self, Read,Write};
use flate2::write::ZlibEncoder;
use flate2::Compression;

#[allow(dead_code)]
fn easter_egg_dead_pool() -> u32 {
    let ade2x: u32 = 0xADEADE;
    let stopinms: u32 = 0xDEADBEEF;
    let mix = 1 * ade2x | stopinms;
    mix.to_le()
}

// 5 Mega Bytes Application
#[allow(dead_code)]
static PSP_HEADER_BIG : [u8;336] =
[
	0x7E, 0x50, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x01, 0x01, 0x22, 0x74, 0x69, 0x66, 0x70, 0x73,
	0x70, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x33, 0x55, 0x00, 0x50, 0x34, 0x55, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x67, 0x3D, 0x00, 0x50, 0x55, 0x0A, 0x01, 0x10, 0x00, 0x40, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x6B, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x4C, 0x6B, 0x3D, 0x00, 0xCC, 0xBB, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00,
	0x90, 0x82, 0x4C, 0x48, 0xA3, 0x53, 0xB2, 0x1B, 0x13, 0x95, 0x2F, 0xF1, 0x0B, 0x90, 0x9C, 0x11,
	0x61, 0x40, 0x20, 0x67, 0xF8, 0xDB, 0xFC, 0x95, 0x5C, 0xBE, 0x8C, 0x80, 0xF3, 0x92, 0x03, 0x01,
	0xB0, 0xBE, 0xF5, 0xF8, 0xA1, 0xAF, 0xAF, 0xA8, 0x38, 0x26, 0x63, 0x09, 0x26, 0x0E, 0xB7, 0xD5,
	0x00, 0x33, 0x55, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x5C, 0x3E, 0x03, 0x22, 0xE5, 0x7D, 0xB9, 0xD1, 0x13, 0x67, 0x97, 0xA3, 0x5B, 0xD8, 0x77, 0x1F,
	0xF0, 0x05, 0xF3, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x4A, 0xD7, 0x37,
	0xC2, 0x8F, 0x15, 0x43, 0x33, 0x93, 0x4D, 0x5B, 0xC0, 0x6E, 0xE4, 0x00, 0xC6, 0x0A, 0x71, 0x11,
	0x98, 0xB6, 0xC3, 0xB7, 0x59, 0x66, 0x21, 0xA8, 0x65, 0xF6, 0x53, 0xA9, 0x7A, 0x48, 0x17, 0xB6,
];

#[allow(dead_code)]
static KIRK_HEADER_BIG : [u8;272] =
[
    0x2A, 0x4F, 0x3C, 0x49, 0x8A, 0x73, 0x4E, 0xD1, 0xF4, 0x55, 0x93, 0x0B, 0x9B, 0x69, 0xDC, 0x65,
    0x73, 0x22, 0x69, 0xD3, 0x73, 0x96, 0x7A, 0x60, 0x66, 0x8C, 0x88, 0xCF, 0x2F, 0x83, 0x58, 0xBC,
    0xB2, 0x00, 0x0A, 0x11, 0x72, 0x43, 0xC5, 0xDE, 0xEF, 0xBB, 0x2C, 0xBF, 0x97, 0x79, 0x6B, 0x9C,
    0x10, 0x1E, 0x7C, 0x57, 0x0E, 0xDB, 0x1D, 0x61, 0x6E, 0xB5, 0xF9, 0x3D, 0x35, 0xE9, 0x5C, 0xD8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x33, 0x55, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7E, 0x50, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x01, 0x01, 0x22, 0x74, 0x69, 0x66, 0x70, 0x73,
    0x70, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x33, 0x55, 0x00, 0x50, 0x34, 0x55, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x67, 0x3D, 0x00, 0x50, 0x55, 0x0A, 0x01, 0x10, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x6B, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4C, 0x6B, 0x3D, 0x00, 0xCC, 0xBB, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00,
];


static KIRK_HEADER_SMALL : [u8;272] = [
	0x9D, 0xC4, 0x48, 0xA6, 0x0E, 0x3C, 0xB7, 0x40, 0x4F, 0x93, 0xFF, 0x56, 0x15, 0x08, 0x28, 0x71, 
	0x3E, 0x52, 0xB5, 0x89, 0xA0, 0x1C, 0xC9, 0xEF, 0x6E, 0x11, 0x0A, 0xC8, 0x28, 0x67, 0x77, 0x66, 
	0xF2, 0xB2, 0x69, 0xCC, 0x08, 0x8C, 0x53, 0xA7, 0xA7, 0x25, 0xF7, 0x2B, 0x84, 0x53, 0x15, 0x54, 
	0x2D, 0x4A, 0xAD, 0xB6, 0x52, 0x40, 0x17, 0xD7, 0xA7, 0xF4, 0xB9, 0x11, 0x17, 0xB7, 0x13, 0x9B, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x09, 0x8F, 0x06, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x7E, 0x50, 0x53, 0x50, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x94, 0x14, 0x11, 0x00, 0x60, 0x90, 0x06, 0x00, 
	0xB8, 0x80, 0x09, 0x00, 0x18, 0xA6, 0x0B, 0x00, 0x70, 0xA1, 0x05, 0x00, 0x10, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x80, 0xAC, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05, 0x0D, 0x00, 0x00, 0x00
];


// Minna no Sukkiri Demo(421KB)
static PSP_HEADER_SMALL : [u8;336] = [
	0x7E, 0x50, 0x53, 0x50, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x6D, 0x61, 0x69, 0x6E, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x94, 0x14, 0x11, 0x00, 0x60, 0x90, 0x06, 0x00, 
	0xB8, 0x80, 0x09, 0x00, 0x18, 0xA6, 0x0B, 0x00, 0x70, 0xA1, 0x05, 0x00, 0x10, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x80, 0xAC, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x05, 0x0D, 0x00, 0x00, 0x00, 
	0x8A, 0x42, 0xAA, 0x13, 0xAE, 0x02, 0x9C, 0x16, 0x99, 0x19, 0x3E, 0xEF, 0xE1, 0xCD, 0xFB, 0xBC, 
	0xDA, 0x28, 0x6E, 0xA5, 0x62, 0x67, 0x71, 0xB2, 0x14, 0x12, 0xAB, 0x7E, 0x1C, 0x69, 0x3A, 0x7A, 
	0xB7, 0x40, 0x8E, 0x91, 0xB1, 0x4F, 0x36, 0xE7, 0x82, 0xF1, 0xFD, 0xB1, 0x50, 0x6D, 0x33, 0xB4, 
	0x09, 0x8F, 0x06, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0xCB, 0x8D, 0xC7, 0x1B, 0x2A, 0xAF, 0x3B, 0x09, 0x2A, 0x5B, 0x4F, 0x9E, 0xE8, 0xE2, 0xCA, 0x66, 
	0xF0, 0x05, 0xF3, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x12, 0xE3, 0x40, 
	0x6E, 0x14, 0x13, 0xEA, 0xA1, 0x81, 0x64, 0x54, 0x57, 0xBE, 0xA2, 0x43, 0x26, 0x7E, 0x4D, 0x0C, 
	0x4F, 0xA6, 0x87, 0x6A, 0xEA, 0x0D, 0xEF, 0xBE, 0x27, 0xE8, 0x78, 0x2D, 0x10, 0x40, 0x05, 0x96
];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Pass `-s ` <source file path> 
    #[arg(short, long,help="Pass `-s ` <source Eboot or Prx file path> ")]
    source: String,
}

// Load Executable File 
fn load_elf(elf: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(elf)?;
    let mut elf = Vec::new();

    file.read_to_end(&mut elf)?;

    Ok(elf)
}

fn get_kirk_size(key_hdr: &[u8]) -> u32 {
    // Ensure that the key_hdr slice has enough data to read a u32 at offset 0x70
    if key_hdr.len() < 0x74 {
        return 0; // or handle this error case appropriately
    }

    let kraw_size = u32::from_le_bytes(key_hdr[0x70..0x74].try_into().unwrap());

    let aligned_size = if kraw_size % 0x10 != 0 {
        kraw_size + (0x10 - (kraw_size % 0x10))
    } else {
        kraw_size
    };

    aligned_size + 0x110
}


/// Make Helper Function
// Todo FN to check if the file is PRX , PFX , or ELF BIN or Else
fn is_psp_prx_file (header_chunk : [u8;336]) -> bool {
    true
}

// Todo FN Check if the file is encyrpted or not if already encrypted do not encyrpt more
fn is_file_encrypted () -> bool{
    let psp_module : PspModuleInfo;    
    let raw_kirk_header_block : [u8;144];
    true
}

// Todo FN check if the file is compressed
fn is_file_compressed(psp_header: &[u8]) ->bool{
    if psp_header.get(6..8).map(|arr| u16::from_le_bytes([arr[0], arr[1]])) == Some(1) {
        return true;
    }
    false
}

fn get_raw_elf_size(psp_header: &[u8]) -> usize {
    if let Some(slice) = psp_header.get(0x28..0x2C) {
        return u32::from_le_bytes(slice.try_into().unwrap_or([0; 4])) as usize;
    }
    // should not go into this
    panic!("Elf File size is 0");
}

fn gzip_compress(dst: &mut [u8], src: &[u8], max_size: usize) -> io::Result<bool> {
    if src.len() > max_size {
        return Ok(false); // Input data exceeds the maximum allowed size.
    }

    let mut encoder = ZlibEncoder::new(dst, Compression::best());
    encoder.write_all(src)?;
    match encoder.finish() {
        Ok(_) => Ok(true), // Compression succeeded.
        Err(_) => Ok(false), // Compression failed.
    }
}

/// PrxEncrypter had limitation of 336bytes prx size ?
fn main() -> io::Result<()> {
    println!(
        "RustPrxEncrypter by gmnprada!"
    );
    println!("For Signing Prx or Eboot.pbp File , for use as Playstation Portable Homebrew to sign Eboot.pbp or Prx File");
    // Theoretically 32 bits max elf size is 0xFFFFFF or MAX Fat32 size or Fat16 size
    // is this intentional ? or the underlying code cannot process buffer of large file
    // cause not create a stream of buffer into signing?
    // need investigation if this intentional or technical limitation of old psp hardware

    // or because of 5MB limit of psp header data used in the hacks? , dunno the real reason behind it ..
    // println!(
    //     "Note : You'r file size should not bigger than {:?} bytes with .prx extension",
    //     0x150 as u32
    // );

    // original code max file size buffer 336bytes
    let max_file_size = 1024 * 1024 * 10;

    // La la la ~ , try it if its work or not , dead men tell no tales, brave captains navigate its own ships ~
    // anyway deadpool exist as i am nothing ~
    // if you want to remove limit of filesize try it by yourself
    // let donot_print_this = easter_egg_deadpool();
    // max_file_size = easter_egg_dead_pool();


    // To Do Parse Args as Buffer and check File
    let args: Args = Args::parse();
    println!("{:?}" ,args);
    
    let elf_file = load_elf(&args.source).expect("Elf File Load Error");

    let init_kirk = kirk_cmd15();
    if init_kirk !=0 {
        panic!("Could not initalize Rs PSP Kirk Library ");
    }

    let kirk_header = KIRK_HEADER_SMALL.clone(); 
    let kirk_header_small_size = get_kirk_size(&kirk_header);

    // if File is already encrypted Inform dev this file already encrypted
    // by teading from psp header types and module info see unused import in rspspkirk/psp_header.rs
    
    if is_file_encrypted() {

    }
    
    // check deadpool is there or not
    if elf_file.len() > max_file_size {
        panic!("You Should Read this code max file size");
    }

    // dunno if this lenght check needed or not anymore
    let mut krawSize: u32 = 0;
    // check for raw kirk header size used can be appended or not
    if elf_file.len() > (kirk_header_small_size - 336) as usize {
        let kirk_header_big_size = get_kirk_size(&kirk_header);
        krawSize = kirk_header_big_size;

        if elf_file.len() > (kirk_header_big_size - 336) as usize {
            panic!("Elf File is Too BIG")
        }
    }

    // To do make options to compress or not 
    let psp_header = PSP_HEADER_SMALL.clone();
    let mut elf_file_pool: Vec<u8> = vec![0; max_file_size];
    if is_file_compressed(&psp_header) {
        let elf_size_value = get_raw_elf_size(&psp_header);
        let _compressed = gzip_compress(&mut elf_file_pool, &elf_file, max_file_size);

        if elf_file_pool.len() > elf_size_value {
            println!("Warn: Compressed File is more big than modified header size in rawKirk file used");
        }

    }

    let mut kirk_raw: Vec<u8> = vec![0; max_file_size];
    let mut kirk_enc: Vec<u8> = vec![0; max_file_size];
    let mut kirk_header_bk = vec![0; 0x90];
    
    // copy head to raw 
    kirk_raw.copy_from_slice(&kirk_header[..0x110]);

    // copy as backup
    kirk_header_bk.copy_from_slice(&kirk_raw);

    // decrypt keys
    let mut keys = [0u8;32];
    let _decrypted = kirk_decrypt_key(&mut keys,&mut kirk_raw );

    //copy decrypted key to raw start
    kirk_raw.copy_from_slice(&keys);
    kirk_raw[0x110..0x110 + elf_file_pool.len()].copy_from_slice(&elf_file_pool);

    let command0 = kirk_cmd0(&mut kirk_enc, &kirk_raw, kirk_enc.len(), false);

    if command0!= 0{
        panic!("Signer : Can't encrypt elf file ");
    }

    kirk_enc.copy_from_slice(&kirk_header_bk);

    // Forge the kirk
    let kirk_enc_len = kirk_enc.len();

    let forge_kirk = kirk_forge(&mut kirk_enc,kirk_enc_len);

    if forge_kirk !=0{
        panic!("Signer : Can't Forge cmac block");
    }

    let mut out_buff: Vec<u8> = vec![0; max_file_size];

    let psp_header_slice = &psp_header[0..0x150];

    out_buff.extend_from_slice(psp_header_slice);

    let kirk_enc_slice = &kirk_enc[0x110..];
    out_buff.extend_from_slice(kirk_enc_slice);

    // Todo THE MOST IMPORTANT PART . Check your homebrew successfully signed or not !
    let output_file = File::create("./data.psp")?;
    let mut output_writer = io::BufWriter::new(output_file);
    output_writer.write_all(&out_buff)?;
    output_writer.flush()?;

    Ok(())

}
