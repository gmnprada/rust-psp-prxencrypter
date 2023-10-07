// Todo and notes
/*

this one is port of PrxEncrypter that i found working on c code when compiled to psp to create signed binary or enrypted prx

the original program include zlib1.dll compiled in date of august 2011
looks like its version is 1.2.5 , if nothing working from crate.io in rust inflate or deflate next things to do is port its dependency too or dynamic linking that 

but its more good if we port it so can compiled and used across different os and machine if i am bored
here is the good references
https://github.com/hachque-Emscripten/zlib-1.2.5/tree/master/src

looks from minpsp sdk also its point into zlib-1.2.5 so better to port some function we actually use from that compression lib to get PrxEncrypter in Pure rust working!

 */

pub mod crypto;
pub mod kirk_engine;
pub mod psp_header;