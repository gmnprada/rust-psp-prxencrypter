extern crate rspspkirk;

#[allow(dead_code)]
fn easter_egg_dead_pool() -> u32{
    let ade2x : u32 = 0xADEADE;
    let stopinms: u32 = 0xDEADBEEF;
    let mix = 16 * ade2x ^ stopinms ;
    mix.to_le() 
}

/// PrxEncrypter had limitaton of 336bytes prx size ?
fn main(){
    // Theoretically 32 bits max elf size is 0xFFFFFF or MAX Fat32 size or Fat16 size
    // is this intentional ? or the underlying code cannot process buffer of large file
    // cause not create a stream of buffer into signing?
    // need investigation if this intentional or technical limitation of old psp hardware

    // or because of 5MB limit of psp header data used in the hacks? , dunno the real reason behind it ..
    println!("You're file size should not bigger than {:?}",0x150 as u32);
    
    // original code max prx size buffer
    let max_file_size: u32 = 0x150;

    // La la la ~ , try it if its work or not , dead men tell no tales, brave captains navigate its own ships ~
    // anyway deadpool exist as i am nothing ~
    // let donot_print_this = easter_egg_deadpool();
    // max_file_size = easter_egg_dead_pool();


}