// this should port the kirk.c and kirk.h from c
// Kirk return values

const KIRK_OPERATION_SUCCESS: u32 = 0;
const KIRK_NOT_ENABLED: u32 = 1;
const KIRK_INVALID_MODE: u32 = 2;
const KIRK_HEADER_HASH_INVALID: u32 = 3;
const KIRK_DATA_HASH_INVALID: u32 = 4;
const KIRK_SIG_CHECK_INVALID: u32 = 5;
const KIRK_UNK_1: u32 = 6;
const KIRK_UNK_2: u32 = 7;
const KIRK_UNK_3: u32 = 8;
const KIRK_UNK_4: u32 = 9;
const KIRK_UNK_5: u32 = 0xA;
const KIRK_UNK_6: u32 = 0xB;
const KIRK_NOT_INITIALIZED: u32 = 0xC;
const KIRK_INVALID_OPERATION: u32 = 0xD;
const KIRK_INVALID_SEED_CODE: u32 = 0xE;
const KIRK_INVALID_SIZE: u32 = 0xF;
const KIRK_DATA_SIZE_ZERO: u32 = 0x10;

#[repr(C)]
pub struct KIRK_AES128CBC_HEADER {
mode: c_int,
unk_4: c_int,
unk_8: c_int,
keyseed: c_int,
data_size: c_int,
}

#[repr(C)]
pub struct KIRK_CMD1_HEADER {
pub AES_key: [u8; 16], //0
pub CMAC_key: [u8; 16], //10
pub CMAC_header_hash: [u8; 16], //20
pub CMAC_data_hash: [u8; 16], //30
pub unused: [u8; 32], //40
pub mode: u32, //60
pub unk3: [u8; 12], //64
pub data_size: u32, //70
pub data_offset: u32, //74
pub unk4: [u8; 8], //78
pub unk5: [u8; 16], //80
} //0x90

#[repr(C)]
pub struct KIRK_SHA1_HEADER {
    data_size: u32, // 0
}

// mode passed to sceUtilsBufferCopyWithRange
const KIRK_CMD_DECRYPT_PRIVATE: u32 = 1;
const KIRK_CMD_ENCRYPT_IV_0: u32 = 4;
const KIRK_CMD_ENCRYPT_IV_FUSE: u32 = 5;
const KIRK_CMD_ENCRYPT_IV_USER: u32 = 6;
const KIRK_CMD_DECRYPT_IV_0: u32 = 7;
const KIRK_CMD_DECRYPT_IV_FUSE: u32 = 8;
const KIRK_CMD_DECRYPT_IV_USER: u32 = 9;
const KIRK_CMD_PRIV_SIG_CHECK: u32 = 10;
const KIRK_CMD_SHA1_HASH: u32 = 11;

//"mode" in header
const KIRK_MODE_CMD1: u32 = 1;
const KIRK_MODE_CMD2: u32 = 2;
const KIRK_MODE_CMD3: u32 = 3;
const KIRK_MODE_ENCRYPT_CBC: u32 = 4;
const KIRK_MODE_DECRYPT_CBC: u32 = 5;

//sceUtilsBufferCopyWithRange errors
const SUBCWR_NOT_16_ALGINED: u32 = 0x90A;
const SUBCWR_HEADER_HASH_INVALID: u32 = 0x920;
const SUBCWR_BUFFER_TOO_SMALL: u32 = 0x1000;


const kirk1_key  :[u8; 16] = [0x98, 0xC9, 0x40, 0x97, 0x5C, 0x1D, 0x10, 0xE8, 0x7F, 0xE6, 0x0E, 0xA3, 0xFD, 0x03, 0xA8, 0xBA];
const kirk7_key03:[u8; 16] = [0x98, 0x02, 0xC4, 0xE6, 0xEC, 0x9E, 0x9E, 0x2F, 0xFC, 0x63, 0x4C, 0xE4, 0x2F, 0xBB, 0x46, 0x68];
const kirk7_key04:[u8; 16] = [0x99, 0x24, 0x4C, 0xD2, 0x58, 0xF5, 0x1B, 0xCB, 0xB0, 0x61, 0x9C, 0xA7, 0x38, 0x30, 0x07, 0x5F];
const kirk7_key05:[u8; 16] = [0x02, 0x25, 0xD7, 0xBA, 0x63, 0xEC, 0xB9, 0x4A, 0x9D, 0x23, 0x76, 0x01, 0xB3, 0xF6, 0xAC, 0x17];
const kirk7_key0C:[u8; 16] = [0x84, 0x85, 0xC8, 0x48, 0x75, 0x08, 0x43, 0xBC, 0x9B, 0x9A, 0xEC, 0xA7, 0x9C, 0x7F, 0x60, 0x18];
const kirk7_key0D:[u8; 16] = [0xB5, 0xB1, 0x6E, 0xDE, 0x23, 0xA9, 0x7B, 0x0E, 0xA1, 0x7C, 0xDB, 0xA2, 0xDC, 0xDE, 0xC4, 0x6E];
const kirk7_key0E:[u8; 16] = [0xC8, 0x71, 0xFD, 0xB3, 0xBC, 0xC5, 0xD2, 0xF2, 0xE2, 0xD7, 0x72, 0x9D, 0xDF, 0x82, 0x68, 0x82];
const kirk7_key0F:[u8; 16] = [0x0A, 0xBB, 0x33, 0x6C, 0x96, 0xD4, 0xCD, 0xD8, 0xCB, 0x5F, 0x4B, 0xE0, 0xBA, 0xDB, 0x9E, 0x03];
const kirk7_key10:[u8; 16] = [0x32, 0x29, 0x5B, 0xD5, 0xEA, 0xF7, 0xA3, 0x42, 0x16, 0xC8, 0x8E, 0x48, 0xFF, 0x50, 0xD3, 0x71];
const kirk7_key11:[u8; 16] = [0x46, 0xF2, 0x5E, 0x8E, 0x4D, 0x2A, 0xA5, 0x40, 0x73, 0x0B, 0xC4, 0x6E, 0x47, 0xEE, 0x6F, 0x0A];
const kirk7_key12:[u8; 16] = [0x5D, 0xC7, 0x11, 0x39, 0xD0, 0x19, 0x38, 0xBC, 0x02, 0x7F, 0xDD, 0xDC, 0xB0, 0x83, 0x7D, 0x9D];
const kirk7_key38:[u8; 16] = [0x12, 0x46, 0x8D, 0x7E, 0x1C, 0x42, 0x20, 0x9B, 0xBA, 0x54, 0x26, 0x83, 0x5E, 0xB0, 0x33, 0x03];
const kirk7_key39:[u8; 16] = [0xC4, 0x3B, 0xB6, 0xD6, 0x53, 0xEE, 0x67, 0x49, 0x3E, 0xA9, 0x5F, 0xBC, 0x0C, 0xED, 0x6F, 0x8A];
const kirk7_key3A:[u8; 16] = [0x2C, 0xC3, 0xCF, 0x8C, 0x28, 0x78, 0xA5, 0xA6, 0x63, 0xE2, 0xAF, 0x2D, 0x71, 0x5E, 0x86, 0xBA];
const kirk7_key4B:[u8; 16] = [0x0C, 0xFD, 0x67, 0x9A, 0xF9, 0xB4, 0x72, 0x4F, 0xD7, 0x8D, 0xD6, 0xE9, 0x96, 0x42, 0x28, 0x8B]; //1.xx game eboot.bin
const kirk7_key53:[u8; 16] = [0xAF, 0xFE, 0x8E, 0xB1, 0x3D, 0xD1, 0x7E, 0xD8, 0x0A, 0x61, 0x24, 0x1C, 0x95, 0x92, 0x56, 0xB6];
const kirk7_key57:[u8; 16] = [0x1C, 0x9B, 0xC4, 0x90, 0xE3, 0x06, 0x64, 0x81, 0xFA, 0x59, 0xFD, 0xB6, 0x00, 0xBB, 0x28, 0x70];
const kirk7_key5D:[u8; 16] = [0x11, 0x5A, 0x5D, 0x20, 0xD5, 0x3A, 0x8D, 0xD3, 0x9C, 0xC5, 0xAF, 0x41, 0x0F, 0x0F, 0x18, 0x6F];
const kirk7_key63:[u8; 16] = [0x9C, 0x9B, 0x13, 0x72, 0xF8, 0xC6, 0x40, 0xCF, 0x1C, 0x62, 0xF5, 0xD5, 0x92, 0xDD, 0xB5, 0x82];
const kirk7_key64:[u8; 16] = [0x03, 0xB3, 0x02, 0xE8, 0x5F, 0xF3, 0x81, 0xB1, 0x3B, 0x8D, 0xAA, 0x2A, 0x90, 0xFF, 0x5E, 0x61];

// ------------------------- INTERNAL STUFF -------------------------


struct HeaderKeys {
    AES: [u8; 16],
    CMAC: [u8; 16],
}

static mut FUSE_ID: [u8; 16] = [0; 16]; // Emulate FUSEID

static mut AES_KIRK1: AES_ctx = AES_ctx::new(); // global

static mut IS_KIRK_INITIALIZED: bool = false; // "init" emulation



// ------------------------- INTERNAL STUFF END -------------------------


use crates::crypto::{AES_cbc_decrypt,AES_set_key,AES_cbc_encrypt};
use std::mem::size_of;

pub fn kirk_cmd0(outbuff: &mut [u8], inbuff: &[u8], size: usize, generate_trash: bool) -> i32 {
    if is_kirk_initialized == 0 {
        return KIRK_NOT_INITIALIZED;
    }

    let header = outbuff.as_ptr() as *mut KIRK_CMD1_HEADER;

    outbuff[..size].copy_from_slice(inbuff);


    unsafe{
        if (*header).mode != KIRK_MODE_CMD1 {
            return KIRK_INVALID_MODE;
        }
    }


    let keys = unsafe { &mut *(outbuff.as_mut_ptr() as *mut header_keys) }; // 0-15 AES key, 16-31 CMAC key

    //FILL PREDATA WITH RANDOM DATA
    if generate_trash {
        unsafe{
            kirk_CMD14(&mut outbuff[size_of::<KIRK_CMD1_HEADER>()..], (*header).data_offset);
        }
    }

    //Make sure data is 16 aligned
    unsafe{
        let mut chk_size = (*header).data_size;
        if chk_size % 16 != 0 {
            chk_size += 16 - (chk_size % 16);
        }
    }


    //ENCRYPT DATA
    let mut k1 = AES_ctx::new();
    AES_set_key(&mut k1, keys.AES, 128);

    unsafe{
        AES_cbc_encrypt(
            &k1,
            &inbuff[size_of::<KIRK_CMD1_HEADER>() + (*header).data_offset..],
            &mut outbuff[size_of::<KIRK_CMD1_HEADER>() + (*header).data_offset..],
            chk_size,
        );
    }


    //CMAC HASHES
    let mut cmac_key = AES_ctx::new();
    AES_set_key(&mut cmac_key, keys.CMAC, 128);

    let mut cmac_header_hash = [0u8; 16];
    let mut cmac_data_hash = [0u8; 16];

    AES_CMAC(
        &cmac_key,
        &outbuff[0x60..][..0x30],
        0x30,
        &mut cmac_header_hash,
    );

    unsafe{
        AES_CMAC(
            &cmac_key,
            &outbuff[0x60..][..0x30 + chk_size + (*header).data_offset],
            &mut cmac_data_hash,
        );
        (*header).CMAC_header_hash.copy_from_slice(&cmac_header_hash);
        (*header).CMAC_data_hash.copy_from_slice(&cmac_data_hash);
    }

    //ENCRYPT KEYS
    AES_cbc_encrypt(&aes_kirk1, &inbuff[..16 * 2], outbuff, 16 * 2);
    KIRK_OPERATION_SUCCESS
}



fn kirk_CMD1(outbuff: &mut [u8], inbuff: &[u8], size: usize, do_check: bool) -> i32 {
    if is_kirk_initialized() == 0 {
        return KIRK_NOT_INITIALIZED;
    }

    let header = unsafe { &*(inbuff.as_ptr() as *const KIRK_CMD1_HEADER) };
    if header.mode != KIRK_MODE_CMD1 {
        return KIRK_INVALID_MODE;
    }

    let mut keys = HeaderKeys {
        AES: [0; 16],
        CMAC: [0; 16],
    };

    unsafe{
        let aes_cmac_keys_ptr: *const u8 = inbuff.as_ptr().add(mem::size_of::<KIRK_CMD1_HEADER>());
        AES_cbc_decrypt(&aes_kirk1, aes_cmac_keys_ptr, &mut keys as *mut _ as *mut u8, 16 * 2);
    }

    if do_check {
        let ret = kirk_CMD10(inbuff, size);
        if ret != KIRK_OPERATION_SUCCESS {
            return ret;
        }
    }


    let mut k1 = Aes128::new_varkey(&keys.aes).unwrap();

    unsafe{
        let data_ptr = inbuff.as_ptr().add(mem::size_of::<KIRK_CMD1_HEADER>() + header.data_offset);
    }

    AES_cbc_decrypt(&mut k1, data_ptr, outbuff, header.data_size);

    return KIRK_OPERATION_SUCCESS;
}

fn kirk_CMD4(outbuff: *mut c_void, inbuff: *const c_void, size: c_int) -> c_int {
    if is_kirk_initialized == 0 {
        return KIRK_NOT_INITIALIZED;
    }

    let header = inbuff as *const KIRK_AES128CBC_HEADER;

    unsafe{
        if (*header).mode != KIRK_MODE_ENCRYPT_CBC {
            return KIRK_INVALID_MODE;
        }
        if (*header).data_size == 0 {
            return KIRK_DATA_SIZE_ZERO;
        }
    }

    let key = unsafe { kirk_4_7_get_key((*header).keyseed) };
    if key == std::ptr::null() {
        return KIRK_INVALID_SIZE;
    }

    // Set the key
    let mut aes_key = AES_ctx::new();
    AES_set_key(&mut aes_key, key, 128);

    // Encrypt the data
    unsafe {
        AES_cbc_encrypt(&aes_key, inbuff.add(std::mem::size_of::<KIRK_AES128CBC_HEADER>()), outbuff, size);
    }

    return KIRK_OPERATION_SUCCESS;
}
