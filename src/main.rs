extern crate rspspkirk;
use clap::Parser;
use std::fs::File;
use std::io::{self, Read};

#[allow(dead_code)]
fn easter_egg_dead_pool() -> u32 {
    let ade2x: u32 = 0xADEADE;
    let stopinms: u32 = 0xDEADBEEF;
    let mix = 16 * ade2x ^ stopinms;
    mix.to_le()
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Pass `-s ` <source file path> 
    #[arg(short, long,help="Pass `-s ` <source file path> ")]
    source: String,
}

fn load_elf(elff: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(elff)?;
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

/// PrxEncrypter had limitation of 336bytes prx size ?
fn main() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    println!(
        "RustPrxEncrypter by gmnprada!"
    );
    println!("For Signing Prx or Eboot.pbp File , for use as Playstation Portable Homebrew");
    // Theoretically 32 bits max elf size is 0xFFFFFF or MAX Fat32 size or Fat16 size
    // is this intentional ? or the underlying code cannot process buffer of large file
    // cause not create a stream of buffer into signing?
    // need investigation if this intentional or technical limitation of old psp hardware

    // or because of 5MB limit of psp header data used in the hacks? , dunno the real reason behind it ..
    // println!(
    //     "Note : You'r file size should not bigger than {:?} bytes with .prx extension",
    //     0x150 as u32
    // );

    // original code max prx size buffer 336bytes
    let max_file_size: u32 = 0x150;

    // La la la ~ , try it if its work or not , dead men tell no tales, brave captains navigate its own ships ~
    // anyway deadpool exist as i am nothing ~
    // if you want to remove limit of filesize try it by yourself
    // let donot_print_this = easter_egg_deadpool();
    // max_file_size = easter_egg_dead_pool();
    let args = Args::parse();
    
}
