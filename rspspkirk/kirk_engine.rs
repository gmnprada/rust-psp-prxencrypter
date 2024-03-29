/// Emulation Of Kirk Engine in PSP Hardware typically started from address 0xbde00000
/// This is bbtgp old shared code in forums
// some ref of implementation also taken from https://www.psdevwiki.com/psp/Kirk
use crate::crypto::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_cmac, aes_set_key, sha1_input, sha1_reset, AesCtx,
    Sha1Context, aes_cmac_forge,
};
use lazy_static::lazy_static;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::Mutex;
use std::time::SystemTime;
use std::{mem::size_of,cmp::Ordering};

const KIRK_OPERATION_SUCCESS: i32 = 0;
const KIRK_NOT_ENABLED: i32 = 1;
const KIRK_INVALID_MODE: i32 = 2;
const KIRK_HEADER_HASH_INVALID: i32 = 3;
const KIRK_DATA_HASH_INVALID: i32 = 4;
const KIRK_SIG_CHECK_INVALID: i32 = 5;
const KIRK_UNK_1: i32 = 6;
const KIRK_UNK_2: i32 = 7;
const KIRK_UNK_3: i32 = 8;
const KIRK_UNK_4: i32 = 9;
const KIRK_UNK_5: i32 = 0xA;
const KIRK_UNK_6: i32 = 0xB;
const KIRK_NOT_INITIALIZED: i32 = 0xC;
const KIRK_INVALID_OPERATION: i32 = 0xD;
const KIRK_INVALID_SEED_CODE: i32 = 0xE;
const KIRK_INVALID_SIZE: i32 = 0xF;
const KIRK_DATA_SIZE_ZERO: i32 = 0x10;

#[repr(C, packed)]
pub struct KirkAes128cbcHeader {
    mode: i32,
    unk_4: i32,
    unk_8: i32,
    keyseed: i32,
    data_size: i32,
}

impl KirkAes128cbcHeader {
    fn to_bytes(self) -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0..=3].copy_from_slice(&self.mode.to_le_bytes());
        buf[4..=7].copy_from_slice(&self.unk_4.to_le_bytes());
        buf[8..=11].copy_from_slice(&self.unk_8.to_le_bytes());
        buf[12..=15].copy_from_slice(&self.keyseed.to_le_bytes());
        buf[16..=19].copy_from_slice(&self.data_size.to_le_bytes());
        buf
    }
}

#[repr(C, packed)]
pub struct KirkCmd1Header {
    pub aes_key: [u8; 16],          //0
    pub cmac_key: [u8; 16],         //10
    pub cmac_header_hash: [u8; 16], //20
    pub cmac_data_hash: [u8; 16],   //30
    pub unused: [u8; 32],           //40
    pub mode: u32,                  //60
    pub unk3: [u8; 12],             //64
    pub data_size: u32,             //70
    pub data_offset: u32,           //74
    pub unk4: [u8; 8],              //78
    pub unk5: [u8; 16],             //80
} //0x90

impl KirkCmd1Header {
    fn to_bytes(self) -> [u8; size_of::<Self>()] {
        let mut bytes: [u8; 144] = [0; size_of::<Self>()];

        bytes[0..15].copy_from_slice(&self.aes_key);
        bytes[15..31].copy_from_slice(&self.cmac_key);
        bytes[31..47].copy_from_slice(&self.cmac_header_hash);
        bytes[47..63].copy_from_slice(&self.cmac_data_hash);
        bytes[63..95].copy_from_slice(&self.unused);
        bytes[95..=99].copy_from_slice(&self.mode.to_le_bytes());
        bytes[99..111].copy_from_slice(&self.unk3);
        bytes[111..115].copy_from_slice(&self.data_size.to_le_bytes());
        bytes[115..119].copy_from_slice(&self.data_offset.to_le_bytes());
        bytes[119..127].copy_from_slice(&self.unk4);
        bytes[127..143].copy_from_slice(&self.unk5);

        bytes
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct KirkSha1Header {
    data_size: u32, // 0
}

// mode passed to sceUtilsBufferCopyWithRange
// some are taken from lib_kirk kirk engine from google repos
const KIRK_CMD_DECRYPT_PRIVATE: u32 = 1;
const KIRK_CMD_2: u32 = 2;
const KIRK_CMD_3: u32 = 3;
const KIRK_CMD_ENCRYPT_IV_0: u32 = 4;
const KIRK_CMD_ENCRYPT_IV_FUSE: u32 = 5;
const KIRK_CMD_ENCRYPT_IV_USER: u32 = 6;
const KIRK_CMD_DECRYPT_IV_0: u32 = 7;
const KIRK_CMD_DECRYPT_IV_FUSE: u32 = 8;
const KIRK_CMD_DECRYPT_IV_USER: u32 = 9;
const KIRK_CMD_PRIV_SIGN_CHECK: u32 = 10;
const KIRK_CMD_SHA1_HASH: u32 = 11;
const KIRK_CMD_ECDSA_GEN_KEYS: u32 = 12;
const KIRK_CMD_ECDSA_MULTIPLY_POINT: u32 = 13;
const KIRK_CMD_PNRG: u32 = 14;
const KIRK_CMD_15: u32 = 15;
const KIRK_CMD_ECDSA_SIGN: u32 = 16;

//"mode" in header
const KIRK_MODE_CMD1: u32 = 1;
const KIRK_MODE_CMD2: u32 = 2;
const KIRK_MODE_CMD3: u32 = 3;
const KIRK_MODE_ENCRYPT_CBC: u32 = 4;
const KIRK_MODE_DECRYPT_CBC: u32 = 5;

//sceUtilsBufferCopyWithRange errors
const SUBCWR_NOT_16_ALIGNED: u32 = 0x90A;
const SUBCWR_HEADER_HASH_INVALID: u32 = 0x920;
const SUBCWR_BUFFER_TOO_SMALL: u32 = 0x1000;

const KIRK1_KEY: [u8; 16] = [
    0x98, 0xC9, 0x40, 0x97, 0x5C, 0x1D, 0x10, 0xE8, 0x7F, 0xE6, 0x0E, 0xA3, 0xFD, 0x03, 0xA8, 0xBA,
];
const KIRK7_KEY03: [u8; 16] = [
    0x98, 0x02, 0xC4, 0xE6, 0xEC, 0x9E, 0x9E, 0x2F, 0xFC, 0x63, 0x4C, 0xE4, 0x2F, 0xBB, 0x46, 0x68,
];
const KIRK7_KEY04: [u8; 16] = [
    0x99, 0x24, 0x4C, 0xD2, 0x58, 0xF5, 0x1B, 0xCB, 0xB0, 0x61, 0x9C, 0xA7, 0x38, 0x30, 0x07, 0x5F,
];
const KIRK7_KEY05: [u8; 16] = [
    0x02, 0x25, 0xD7, 0xBA, 0x63, 0xEC, 0xB9, 0x4A, 0x9D, 0x23, 0x76, 0x01, 0xB3, 0xF6, 0xAC, 0x17,
];
const KIRK7_KEY0C: [u8; 16] = [
    0x84, 0x85, 0xC8, 0x48, 0x75, 0x08, 0x43, 0xBC, 0x9B, 0x9A, 0xEC, 0xA7, 0x9C, 0x7F, 0x60, 0x18,
];
const KIRK7_KEY0D: [u8; 16] = [
    0xB5, 0xB1, 0x6E, 0xDE, 0x23, 0xA9, 0x7B, 0x0E, 0xA1, 0x7C, 0xDB, 0xA2, 0xDC, 0xDE, 0xC4, 0x6E,
];
const KIRK7_KEY0E: [u8; 16] = [
    0xC8, 0x71, 0xFD, 0xB3, 0xBC, 0xC5, 0xD2, 0xF2, 0xE2, 0xD7, 0x72, 0x9D, 0xDF, 0x82, 0x68, 0x82,
];
const KIRK7_KEY0F: [u8; 16] = [
    0x0A, 0xBB, 0x33, 0x6C, 0x96, 0xD4, 0xCD, 0xD8, 0xCB, 0x5F, 0x4B, 0xE0, 0xBA, 0xDB, 0x9E, 0x03,
];
const KIRK7_KEY10: [u8; 16] = [
    0x32, 0x29, 0x5B, 0xD5, 0xEA, 0xF7, 0xA3, 0x42, 0x16, 0xC8, 0x8E, 0x48, 0xFF, 0x50, 0xD3, 0x71,
];
const KIRK7_KEY11: [u8; 16] = [
    0x46, 0xF2, 0x5E, 0x8E, 0x4D, 0x2A, 0xA5, 0x40, 0x73, 0x0B, 0xC4, 0x6E, 0x47, 0xEE, 0x6F, 0x0A,
];
const KIRK7_KEY12: [u8; 16] = [
    0x5D, 0xC7, 0x11, 0x39, 0xD0, 0x19, 0x38, 0xBC, 0x02, 0x7F, 0xDD, 0xDC, 0xB0, 0x83, 0x7D, 0x9D,
];
const KIRK7_KEY38: [u8; 16] = [
    0x12, 0x46, 0x8D, 0x7E, 0x1C, 0x42, 0x20, 0x9B, 0xBA, 0x54, 0x26, 0x83, 0x5E, 0xB0, 0x33, 0x03,
];
const KIRK7_KEY39: [u8; 16] = [
    0xC4, 0x3B, 0xB6, 0xD6, 0x53, 0xEE, 0x67, 0x49, 0x3E, 0xA9, 0x5F, 0xBC, 0x0C, 0xED, 0x6F, 0x8A,
];
const KIRK7_KEY3A: [u8; 16] = [
    0x2C, 0xC3, 0xCF, 0x8C, 0x28, 0x78, 0xA5, 0xA6, 0x63, 0xE2, 0xAF, 0x2D, 0x71, 0x5E, 0x86, 0xBA,
];
const KIRK7_KEY4B: [u8; 16] = [
    0x0C, 0xFD, 0x67, 0x9A, 0xF9, 0xB4, 0x72, 0x4F, 0xD7, 0x8D, 0xD6, 0xE9, 0x96, 0x42, 0x28, 0x8B,
];
const KIRK7_KEY53: [u8; 16] = [
    0xAF, 0xFE, 0x8E, 0xB1, 0x3D, 0xD1, 0x7E, 0xD8, 0x0A, 0x61, 0x24, 0x1C, 0x95, 0x92, 0x56, 0xB6,
];
const KIRK7_KEY57: [u8; 16] = [
    0x1C, 0x9B, 0xC4, 0x90, 0xE3, 0x06, 0x64, 0x81, 0xFA, 0x59, 0xFD, 0xB6, 0x00, 0xBB, 0x28, 0x70,
];
const KIRK7_KEY5D: [u8; 16] = [
    0x11, 0x5A, 0x5D, 0x20, 0xD5, 0x3A, 0x8D, 0xD3, 0x9C, 0xC5, 0xAF, 0x41, 0x0F, 0x0F, 0x18, 0x6F,
];
const KIRK7_KEY63: [u8; 16] = [
    0x9C, 0x9B, 0x13, 0x72, 0xF8, 0xC6, 0x40, 0xCF, 0x1C, 0x62, 0xF5, 0xD5, 0x92, 0xDD, 0xB5, 0x82,
];
const KIRK7_KEY64: [u8; 16] = [
    0x03, 0xB3, 0x02, 0xE8, 0x5F, 0xF3, 0x81, 0xB1, 0x3B, 0x8D, 0xAA, 0x2A, 0x90, 0xFF, 0x5E, 0x61,
];

// ------------------------- INTERNAL STUFF -------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct HeaderKeys {
    pub aes: [u8; 16],
    pub cmac: [u8; 16],
}

impl HeaderKeys {
    pub fn to_bytes(self) -> [u8; size_of::<Self>()] {
        let mut bytes: [u8; 32] = [0; size_of::<Self>()];
        //TODO make the slice from self to bytes
        bytes
    }
}

// Static Global Emulate Fuse ID Refrence
lazy_static! {
    static ref FUSE_ID: Mutex<[u8; 16]> = Mutex::new([0; 16]);
    static ref AES_KIRK1: Mutex<AesCtx> = Mutex::new(AesCtx::new());
    static ref IS_KIRK_INITIALIZED: Mutex<bool> = Mutex::new(false);
    static ref RNG_SEED: Mutex<StdRng> = Mutex::new(StdRng::seed_from_u64(0));
}

// this is placeholder actuall error code not known yet
const INVALID_ERROR: [u8; 16] = [
    0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Helper Function
fn kirk_4_7_get_key(key_type: i32) -> [u8; 16] {
    match key_type {
        0x03 => KIRK7_KEY03,
        0x04 => KIRK7_KEY04,
        0x05 => KIRK7_KEY05,
        0x0C => KIRK7_KEY0C,
        0x0D => KIRK7_KEY0D,
        0x0E => KIRK7_KEY0E,
        0x0F => KIRK7_KEY0F,
        0x10 => KIRK7_KEY10,
        0x11 => KIRK7_KEY11,
        0x12 => KIRK7_KEY12,
        0x38 => KIRK7_KEY38,
        0x39 => KIRK7_KEY39,
        0x3A => KIRK7_KEY3A,
        0x4B => KIRK7_KEY4B,
        0x53 => KIRK7_KEY53,
        0x57 => KIRK7_KEY57,
        0x5D => KIRK7_KEY5D,
        0x63 => KIRK7_KEY63,
        0x64 => KIRK7_KEY64,
        _ => INVALID_ERROR,
    }
}

// ------------------------- INTERNAL STUFF END -------------------------

/// Super-Duper decryption (no inverse)
// need to reimplement the c code into rust carefully cause of data types , alignment , padding and pointer
// done cureated by hand not tested yet
// we can remove unsafe later if can be moved into safe operation
pub fn kirk_cmd0(outbuff: &mut [u8], inbuff: &[u8], size: usize, generate_trash: bool) -> i32 {
    let inited = IS_KIRK_INITIALIZED.lock().unwrap().to_owned();
    if inited == false {
        return KIRK_NOT_INITIALIZED;
    }

    let header = outbuff.as_ptr() as *mut KirkCmd1Header;

    outbuff[..size].copy_from_slice(inbuff);

    unsafe {
        if (*header).mode != KIRK_MODE_CMD1 {
            return KIRK_INVALID_MODE;
        }
    }

    let keys = unsafe { &mut *(outbuff.as_mut_ptr() as *mut HeaderKeys) }; // 0-15 AES key, 16-31 CMAC key

    //FILL PREDATA WITH RANDOM DATA
    if generate_trash {
        unsafe {
            kirk_cmd14(
                &mut outbuff[size_of::<KirkCmd1Header>()..],
                (*header).data_offset as usize,
            );
        }
    }

    //Make sure data is 16 aligned
    let mut chk_size: usize;
    unsafe {
        chk_size = (*header).data_size as usize;
        if chk_size % 16 != 0 {
            chk_size += 16 - (chk_size % 16);
        }
    }

    //ENCRYPT DATA
    //This one is filled with 0x00 bytes
    let mut k1: AesCtx = AesCtx::new();

    // set key here!
    aes_set_key(&mut k1, &keys.aes, 128);

    unsafe {
        aes_cbc_encrypt(
            &k1,
            &inbuff[size_of::<KirkCmd1Header>() + (*header).data_offset as usize..],
            &mut outbuff[size_of::<KirkCmd1Header>() + (*header).data_offset as usize..],
            chk_size.try_into().unwrap(),
        );
    }

    //CMAC HASHES
    let mut cmac_key = AesCtx::new();
    aes_set_key(&mut cmac_key, &keys.cmac, 128);

    let mut cmac_header_hash = [0u8; 16];
    let mut cmac_data_hash = [0u8; 16];

    aes_cmac(
        &mut cmac_key,
        &outbuff[0x60..][..0x30],
        0x30,
        &mut cmac_header_hash,
    );

    unsafe {
        let cmac_next_lenght = 0x30 + chk_size + (*header).data_offset as usize;
        aes_cmac(
            &mut cmac_key,
            &outbuff[0x60..],
            cmac_next_lenght,
            &mut cmac_data_hash,
        );
        (*header)
            .cmac_header_hash
            .copy_from_slice(&cmac_header_hash);
        (*header).cmac_data_hash.copy_from_slice(&cmac_data_hash);
    }

    //GET GLOBAL REFRENCE
    let g_aes_kirk1 = AES_KIRK1.lock().unwrap().to_owned();
    //ENCRYPT KEYS
    aes_cbc_encrypt(&g_aes_kirk1, &inbuff[..16 * 2], outbuff, 16 * 2);

    KIRK_OPERATION_SUCCESS
}

pub fn kirk_cmd1(outbuff: &mut [u8], inbuff: &[u8], size: usize, do_check: bool) -> i32 {
    let inited = IS_KIRK_INITIALIZED.lock().unwrap().to_owned();
    if inited == false {
        return KIRK_NOT_INITIALIZED;
    }

    let header = unsafe { &*(inbuff.as_ptr() as *const KirkCmd1Header) };

    if header.mode != KIRK_MODE_CMD1 {
        return KIRK_INVALID_MODE;
    }

    // do check with kirk_cmd10
    if do_check {
        let check = kirk_cmd10(inbuff, size);
        if check != KIRK_OPERATION_SUCCESS {
            return check;
        }
    }

    let keys = HeaderKeys {
        aes: [0; 16],
        cmac: [0; 16],
    };

    //GET GLOBAL REFRENCE
    let g_aes_kirk1 = AES_KIRK1.lock().unwrap().to_owned();

    //DECRYPT
    aes_cbc_decrypt(&g_aes_kirk1, inbuff, &mut keys.to_bytes(), 16 * 2);

    if do_check {
        let ret = kirk_cmd10(inbuff, size);
        if ret != KIRK_OPERATION_SUCCESS {
            return ret;
        }
    }

    let mut k1 = AesCtx::new();
    aes_set_key(&mut k1, &keys.aes, 128);

    let dataptr = size_of::<KirkCmd1Header>() + header.data_offset as usize;
    aes_cbc_decrypt(&k1, &inbuff[..dataptr], outbuff, header.data_size as usize);

    return KIRK_OPERATION_SUCCESS;
}

// kirk_CMD2? // todo
// kirk_CMD3? // todo

/// KIRK_CMD_ENCRYPT_STATIC
/// Encrypt Operation (inverse of cmd 7) (key=static)
fn kirk_cmd4(outbuff: &mut [u8], inbuff: &[u8], size: usize) -> i32 {
    let inited = IS_KIRK_INITIALIZED.lock().unwrap().to_owned();
    if inited == false {
        return KIRK_NOT_INITIALIZED;
    };

    let header = unsafe { &*(inbuff.as_ptr() as *const KirkAes128cbcHeader) };

    if header.mode != KIRK_MODE_ENCRYPT_CBC as i32 {
        return KIRK_INVALID_MODE;
    };

    if header.data_size == 0 {
        return KIRK_DATA_SIZE_ZERO;
    };

    let key = kirk_4_7_get_key(header.keyseed);
    if key == INVALID_ERROR {
        return KIRK_INVALID_SIZE;
    };

    let mut ctx = AesCtx::new();

    aes_set_key(&mut ctx, &key, 128);

    // grab the + in c code to point into inbuf data
    let sizeptr = size_of::<KirkAes128cbcHeader>();
    aes_cbc_encrypt(&ctx, &inbuff[..sizeptr], outbuff, size);

    KIRK_OPERATION_SUCCESS
}

// kirk cmd5 ? todo its a guessing works after all not exist in c code by bbtgp but devwiki may contains

// kirk cmd6 ? todo its a guessing works after all not exist in c code by bbtgp but devwiki may contains

/// KIRK_CMD_DECRYPT_STATIC
/// Decrypt Operation (inverse of cmd 4) (key=static)
fn kirk_cmd7(outbuff: &mut [u8], inbuff: &[u8], size: usize) -> i32 {
    let inited = IS_KIRK_INITIALIZED.lock().unwrap().to_owned();
    if inited == false {
        return KIRK_NOT_INITIALIZED;
    };

    let header: &KirkAes128cbcHeader = unsafe { &*(inbuff.as_ptr() as *const KirkAes128cbcHeader) };

    if header.mode != KIRK_MODE_DECRYPT_CBC as i32 {
        return KIRK_INVALID_MODE;
    };
    if header.data_size == 0 {
        return KIRK_DATA_SIZE_ZERO;
    };

    let key = kirk_4_7_get_key(header.keyseed);
    if key == INVALID_ERROR {
        return KIRK_INVALID_SIZE;
    };

    let mut ctx = AesCtx::new();

    aes_set_key(&mut ctx, &key, 128);

    // grab the + in c code to point into inbuf data
    let sizeptr = size_of::<KirkAes128cbcHeader>();
    aes_cbc_decrypt(&ctx, &inbuff[..sizeptr], outbuff, size);

    KIRK_OPERATION_SUCCESS
}

/// Kirk Command 10: AES CMAC verification
/// This seems to be the AES CMAC verification of CMD1, and takes the same header as CMD1, the only difference is that no decryption is performed.
/// See command 1 information for details.
/// It could also possibly verify CMACs for commands 2 & 3, but that is unknown.
fn kirk_cmd10(inbuff: &[u8], size: usize) -> i32 {
    let inited = IS_KIRK_INITIALIZED.lock().unwrap().to_owned();
    if inited == false {
        return KIRK_NOT_INITIALIZED;
    }

    let header = unsafe { &*(inbuff.as_ptr() as *const KirkCmd1Header) };

    if !(header.mode == KIRK_MODE_CMD1
        || header.mode == KIRK_MODE_CMD2
        || header.mode == KIRK_MODE_CMD3)
    {
        return KIRK_INVALID_MODE;
    }

    if header.data_size == 0 {
        return KIRK_DATA_SIZE_ZERO;
    };

    if header.mode == KIRK_MODE_CMD1 {
        let mut keys = HeaderKeys {
            aes: [0u8; 16],
            cmac: [0u8; 16],
        };

        let mut keys_buffer = [0u8; 32];

        let mut g_aes_kirk1 = AES_KIRK1.lock().unwrap().to_owned();

        aes_cbc_decrypt(&mut g_aes_kirk1, inbuff, &mut keys_buffer, size);

        keys.aes.copy_from_slice(&keys_buffer[0..16]);
        keys.cmac.copy_from_slice(&keys_buffer[16..32]);

        // Initialize new aes context
        let mut cmac_key = AesCtx::new();
        aes_set_key(&mut cmac_key, &mut keys.cmac, 128);

        let mut cmac_header_hash = [0u8; 16];
        let mut cmac_data_hash = [0u8; 16];

        //fill header data hash
        aes_cmac(&mut cmac_key, &inbuff[..0x60], 0x30, &mut cmac_header_hash);

        // make sure the data 16 aligned
        let mut chk_size = header.data_size;
        if chk_size % 16 != 0 {
            chk_size += 16 - (chk_size % 16);
        }

        // fill cmac_data_hash
        let calc_length = (0x30 + chk_size + header.data_offset) as usize;
        aes_cmac(
            &mut cmac_key,
            &inbuff[..0x60],
            calc_length,
            &mut cmac_data_hash,
        );

        if cmac_header_hash != header.cmac_header_hash {
            println!("Header Hash Invalid");
            return KIRK_HEADER_HASH_INVALID;
        }

        if cmac_data_hash != header.cmac_data_hash {
            println!("data hash invalid");
            return KIRK_DATA_HASH_INVALID;
        }

        return KIRK_OPERATION_SUCCESS;
    }
    KIRK_SIG_CHECK_INVALID
}

fn kirk_cmd11(outbuff: &mut [u8], inbuff: &[u8], size: usize) -> i32 {
    let inited = IS_KIRK_INITIALIZED.lock().unwrap().to_owned();
    if inited == false {
        return KIRK_NOT_INITIALIZED;
    }

    let header = unsafe { &*(inbuff.as_ptr() as *const KirkSha1Header) };

    if header.data_size == 0 || size == 0 {
        return KIRK_DATA_SIZE_ZERO;
    }

    let mut sha = Sha1Context::default();
    sha1_reset(&mut sha);

    let mut sizenew = size;
    sizenew <<= 4;
    sizenew >>= 4;
    sizenew = if sizenew < header.data_size as usize {
        sizenew
    } else {
        header.data_size as usize
    };

    sha1_input(&mut sha, &inbuff[..4], sizenew);
    KIRK_OPERATION_SUCCESS
}

fn kirk_cmd14(outbuff: &mut [u8], size: usize) -> i32 {
    let inited = IS_KIRK_INITIALIZED.lock().unwrap().to_owned();

    if inited == false {
        return KIRK_NOT_INITIALIZED;
    }

    // grab init rng seed
    let mut _g_rng = RNG_SEED.lock().unwrap().to_owned();

    // create tempt i32 array as defined in size
    let mut temp: Vec<i32> = vec![0; size];

    // generate random number 4 bytes size and write to temp vector
    for i in temp.iter_mut() {
        let rand: i32 = _g_rng.gen();
        *i = rand % 255;
    }

    // Copy the contents of temp into outbuff element by element
    for (dest_chunk, src) in outbuff.chunks_mut(4).zip(temp.iter()) {
        let bytes = src.to_le_bytes();
        dest_chunk[..bytes.len()].copy_from_slice(&bytes);
    }

    KIRK_OPERATION_SUCCESS
}

// TODO kirk_CMD15 this is equivalent to kirk_init on wiki
pub fn kirk_cmd15() -> i32 {
    // get global aes context
    let mut g_aes_kirk1 = AES_KIRK1.lock().unwrap();

    // put the key
    aes_set_key(&mut g_aes_kirk1, &KIRK1_KEY, 128);

    // flag RNG initialized
    let mut g_inited = IS_KIRK_INITIALIZED.lock().unwrap();
    *g_inited = true;

    // Initalize the Psuedo random generator seed from system time
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to Configure System Time Duration as Seed");

    // grab rng seed refrences
    let mut g_rng = RNG_SEED.lock().unwrap();

    // generate seed from system time unix epoch
    *g_rng = StdRng::seed_from_u64(d.as_secs());

    // RETURN KIRK INITED
    KIRK_OPERATION_SUCCESS
}

// set Fuse data , this data can be acquired through psp motherboard
fn sce_utils_set_fuse_id(fuse_value: &[u8; 16]) -> i32 {
    let mut g_fuse = FUSE_ID.lock().unwrap();

    // Fake fuse id append it with 6d 79 73 65 6c 66 become ??? , congrats you are a lone wolf!
    *g_fuse = [
        0x46, 0x69, 0x6e, 0x65, 0x20, 0x49, 0x27, 0x6c, 0x6c, 0x20, 0x64, 0x6f, 0x20, 0x69, 0x74,
        0x20,
    ];

    // just let it here donot convert this bytes to read in string! you have been warned! ~lol
    *g_fuse = [
        0x30, 0x78, 0x41, 0x44, 0x45, 0x41, 0x44, 0x45, 0x20, 0x30, 0x78, 0x44, 0x41, 0x44, 0x42,
        0x45,
    ];

    println!("Set fuse_id too {:?}", fuse_value);

    // if you want to fake it the fuse id just comment this line
    *g_fuse = *fuse_value;
    0
}

// Buffering Method used by psp emulated
fn sce_utils_buffer_copy_with_range(outbuff: &mut [u8],inbuff: &[u8],insize:usize,kirk_cmd : u32) -> i32 {
    match kirk_cmd {
        KIRK_CMD_DECRYPT_PRIVATE => {
            if inbuff.len() % 16 != 0 {
                return SUBCWR_NOT_16_ALIGNED as i32;
            }

            let ret = kirk_cmd1(outbuff, inbuff,insize,true);
            if ret == KIRK_HEADER_HASH_INVALID {
                return SUBCWR_HEADER_HASH_INVALID as i32;
            }
            return ret;
        },
        KIRK_CMD_ENCRYPT_IV_0 => kirk_cmd4(outbuff, inbuff,insize),
        KIRK_CMD_DECRYPT_IV_0 => kirk_cmd7(outbuff, inbuff,insize),
        KIRK_CMD_PRIV_SIGN_CHECK => kirk_cmd10(inbuff,insize),
        KIRK_CMD_SHA1_HASH => kirk_cmd11(outbuff, inbuff,insize),
        _ => {
            println!("Unknown Kirk CMD or unimplemented");
            return -1
        },
    }
}

// TODO add Function KIRK_FORGE
pub fn kirk_forge( inbuff: &mut [u8], size: usize) -> i32 {
    let header = unsafe { &*(inbuff.as_ptr() as *const KirkCmd1Header) };
    let mut cmac_key: AesCtx = AesCtx::new();


    let mut cmac_header_hash = [0u8; 16];
    let mut cmac_data_hash = [0u8; 16];

    let inited = IS_KIRK_INITIALIZED.lock().unwrap().to_owned();

    if inited == false {
        return KIRK_NOT_INITIALIZED;
    }

    if !(header.mode == KIRK_MODE_CMD1
        || header.mode == KIRK_MODE_CMD2
        || header.mode == KIRK_MODE_CMD3)
    {
        return KIRK_INVALID_MODE;
    }

    if (header.data_size == 0 || size == 0) {
        return KIRK_DATA_SIZE_ZERO;
    }

    if header.mode == KIRK_MODE_CMD1 {
        let mut keys = HeaderKeys {
            aes: [0; 16],
            cmac: [0; 16],
        };

        let mut g_aes_kirk1 = AES_KIRK1.lock().unwrap();

        aes_cbc_decrypt(&g_aes_kirk1, inbuff, &mut keys.to_bytes(), 16 * 2);
        aes_set_key(& mut cmac_key,&keys.cmac , 128);
        aes_cmac(&mut cmac_key, &inbuff[..0x60], 0x30, &mut cmac_header_hash);


        let mut chksize  = header.data_size;

        if(chksize % 16 == 0) {
            chksize += 16 - (chksize % 16);
            println!("Data Is Valid 16 bits Aligned");
        }

        let data_length = (0x30 + chksize + header.data_offset) as usize;
        aes_cmac(&mut cmac_key, &inbuff[..0x60],data_length, &mut cmac_data_hash);

        if cmac_header_hash != header.cmac_header_hash {
            //println!("Data Hash Invalid");
        }else{
            // data hash invalid
            println!("Data Hash Already Invalid Aborting Operation");
            return 100;
        }

        // copy data
        cmac_data_hash.copy_from_slice(&header.cmac_data_hash);
        aes_cmac_forge(&mut cmac_key, &mut inbuff[..0x60], data_length as i32, &mut cmac_data_hash);
        return KIRK_OPERATION_SUCCESS;
    }

    KIRK_SIG_CHECK_INVALID

}

pub fn kirk_decrypt_key(keys: &mut [u8], inbuff: &mut [u8]) -> i32 {
    let g_aes_kirk1 = AES_KIRK1.lock().unwrap();
    aes_cbc_decrypt(&g_aes_kirk1,inbuff, keys, 32);
    0
}