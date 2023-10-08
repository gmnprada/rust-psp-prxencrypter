# Rust Prx Encrypter
Port of C PSP PrxEncrypter tools into pure rust its to create SIGNED binary for PSP Eboot
or Sign a PRX Module.

## Build
```
cargo build
```

## Usage
WIP Help Me Design the API command in claps?
```
rsprxencyrpter -s <pathtofile>
```

## Todo List 
- []Implement full hashing standard FIPS PUB 180-1 published April 17, 1995 optimized in rust the rijndael (aes) and sha1 used in signing , even its legacy and insecure . our goals is to easily sign homebrew here, and remove some caveats and portability issues on non 32bits processor , maybe through emulating some or align and padding accordingly see rspspkirk/crypto.rs for more insight.
- []optional create PrxDecrypter in pure rust

## Goals
- [] write it in pure rust.
- [] Sign PSP Homebrew to run on Official Playstation Portable Firmware easily.
- [] Make sign EBOOT.PBP files to run on unmodified PSPs checkmark in rust-psp crates
- [] easily build , and compile, mantain this tools for the homebrew development project using rust programing lang targeting Playstation Portable mipsel-sony-psp

### Thanks
Credits to alls big shoulder who had been in PSP Scenes that share info online , either Hacking , Developing , Create the SDK or share document the hardware, ~ You're Cools

```
- pspdev wiki
- bbtgp from the code from wololo forum
- kirk_engine from google svn
- the team that write emulator in C++
- all reverse engineer gods in PSP scene that on homebrew scene
- and ~PSP to create the closed box
```