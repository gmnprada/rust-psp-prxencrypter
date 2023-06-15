#![crate_type="lib"]
/*	$OpenBSD: rijndael.c,v 1.19 2008/06/09 07:49:45 djm Exp $ */


/**
 * rijndael-alg-fst.c
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

 /*
 *  sha1.c
 *
 *  Copyright (C) 1998, 2009
 *  Paul E. Jones <paulej@packetizer.com>
 *  All Rights Reserved
 *
 *****************************************************************************
 *  $Id: sha1.c 12 2009-06-22 19:34:25Z paulej $
 *****************************************************************************
 *
 *  Description:
 *      This file implements the Secure Hashing Standard as defined
 *      in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The Secure Hashing Standard, which uses the Secure Hashing
 *      Algorithm (SHA), produces a 160-bit message digest for a
 *      given data stream.  In theory, it is highly improbable that
 *      two messages will produce the same message digest.  Therefore,
 *      this algorithm can serve as a means of providing a "fingerprint"
 *      for a message.
 *
 *  Portability Issues:
 *      SHA-1 is defined in terms of 32-bit "words".  This code was
 *      written with the expectation that the processor has at least
 *      a 32-bit machine word size.  If the machine word size is larger,
 *      the code should still function properly.  One caveat to that
 *      is that the input functions taking characters and character
 *      arrays assume that only 8 bits of information are stored in each
 *      character.
 *
 *  Caveats:
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long. Although SHA-1 allows a message digest to be generated for
 *      messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is a
 *      multiple of the size of an 8-bit character.
 *
 */


// To rust port for rust-prx-encrypter (Signed Eboot To PSP)
// Ported to rust in 2023 by GMNP not fully tested yet the correctness of the binary produced
// as many of type casted to usize here which in rust can be 4 bytes or 8 bytes depend on machine its run should we always use 4 bytes and 1bytes length like u32, s32 ,and u8?
// nothing is clear yet except we already wrote the test by checking the compiled result

use std::convert::TryInto;

// crypto.h
const AES_KEY_LEN_128: usize = 128;
const AES_KEY_LEN_192: usize = 192;
const AES_KEY_LEN_256: usize = 256;
const AES_BUFFER_SIZE: usize = 16;
const AES_MAXKEYBITS: usize = 256;
const AES_MAXKEYBYTES: usize = AES_MAXKEYBITS / 8;
const AES_MAXROUNDS: usize = 14;

// crypto.c
const AES_128: u8 = 0;
const CONST_RB: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
];
const CONST_ZERO: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
#[repr(C)]
pub struct RijndaelCtx {
    pub enc_only: i32,
    pub nr: i32,
    pub ek: [u32; 4 * (AES_MAXROUNDS + 1)],
    pub dk: [u32; 4 * (AES_MAXROUNDS + 1)],
}

// fill it with 0x00 bytes in default
// shoul we fill it with random data ?
impl RijndaelCtx {
    pub fn new() -> RijndaelCtx {
        RijndaelCtx {
            enc_only: 0,
            nr: 0,
            ek: [0; 4 * (AES_MAXROUNDS + 1)],
            dk: [0; 4 * (AES_MAXROUNDS + 1)],
        }
    }
}

impl From<RijndaelCtx> for AesCtx {
    fn from(val: RijndaelCtx) -> AesCtx {
        AesCtx {
            enc_only: val.enc_only,
            nr: val.nr,
            ek: val.ek,
            dk: val.dk,
        }
    }
}
pub type PwuAESContextBuffer = RijndaelCtx;

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
#[repr(C)]
pub struct AesCtx {
    pub enc_only: i32,
    pub nr: i32,
    pub ek: [u32; 4 * (AES_MAXROUNDS + 1)],
    pub dk: [u32; 4 * (AES_MAXROUNDS + 1)],
}

// fill it with 0x00 bytes 
// shoul we fill it with random data , dunno yet ..
impl AesCtx {
    pub fn new() -> AesCtx {
        AesCtx {
            enc_only: 0,
            nr: 0,
            ek: [0; 4 * (AES_MAXROUNDS + 1)],
            dk: [0; 4 * (AES_MAXROUNDS + 1)],
        }
    }
}

impl From<AesCtx> for RijndaelCtx {
    fn from(val: AesCtx) -> RijndaelCtx {
        RijndaelCtx {
            enc_only: val.enc_only,
            nr: val.nr,
            ek: val.ek,
            dk: val.dk,
        }
    }
}

// should return unsigned 32 bits the c suffix is only unsigned so this can be different on bit width
static TE0: [u32; 256] = [
    0xc66363a5_u32,
    0xf87c7c84_u32,
    0xee777799_u32,
    0xf67b7b8d_u32,
    0xfff2f20d_u32,
    0xd66b6bbd_u32,
    0xde6f6fb1_u32,
    0x91c5c554_u32,
    0x60303050_u32,
    0x02010103_u32,
    0xce6767a9_u32,
    0x562b2b7d_u32,
    0xe7fefe19_u32,
    0xb5d7d762_u32,
    0x4dababe6_u32,
    0xec76769a_u32,
    0x8fcaca45_u32,
    0x1f82829d_u32,
    0x89c9c940_u32,
    0xfa7d7d87_u32,
    0xeffafa15_u32,
    0xb25959eb_u32,
    0x8e4747c9_u32,
    0xfbf0f00b_u32,
    0x41adadec_u32,
    0xb3d4d467_u32,
    0x5fa2a2fd_u32,
    0x45afafea_u32,
    0x239c9cbf_u32,
    0x53a4a4f7_u32,
    0xe4727296_u32,
    0x9bc0c05b_u32,
    0x75b7b7c2_u32,
    0xe1fdfd1c_u32,
    0x3d9393ae_u32,
    0x4c26266a_u32,
    0x6c36365a_u32,
    0x7e3f3f41_u32,
    0xf5f7f702_u32,
    0x83cccc4f_u32,
    0x6834345c_u32,
    0x51a5a5f4_u32,
    0xd1e5e534_u32,
    0xf9f1f108_u32,
    0xe2717193_u32,
    0xabd8d873_u32,
    0x62313153_u32,
    0x2a15153f_u32,
    0x0804040c_u32,
    0x95c7c752_u32,
    0x46232365_u32,
    0x9dc3c35e_u32,
    0x30181828_u32,
    0x379696a1_u32,
    0x0a05050f_u32,
    0x2f9a9ab5_u32,
    0x0e070709_u32,
    0x24121236_u32,
    0x1b80809b_u32,
    0xdfe2e23d_u32,
    0xcdebeb26_u32,
    0x4e272769_u32,
    0x7fb2b2cd_u32,
    0xea75759f_u32,
    0x1209091b_u32,
    0x1d83839e_u32,
    0x582c2c74_u32,
    0x341a1a2e_u32,
    0x361b1b2d_u32,
    0xdc6e6eb2_u32,
    0xb45a5aee_u32,
    0x5ba0a0fb_u32,
    0xa45252f6_u32,
    0x763b3b4d_u32,
    0xb7d6d661_u32,
    0x7db3b3ce_u32,
    0x5229297b_u32,
    0xdde3e33e_u32,
    0x5e2f2f71_u32,
    0x13848497_u32,
    0xa65353f5_u32,
    0xb9d1d168_u32,
    0x00000000_u32,
    0xc1eded2c_u32,
    0x40202060_u32,
    0xe3fcfc1f_u32,
    0x79b1b1c8_u32,
    0xb65b5bed_u32,
    0xd46a6abe_u32,
    0x8dcbcb46_u32,
    0x67bebed9_u32,
    0x7239394b_u32,
    0x944a4ade_u32,
    0x984c4cd4_u32,
    0xb05858e8_u32,
    0x85cfcf4a_u32,
    0xbbd0d06b_u32,
    0xc5efef2a_u32,
    0x4faaaae5_u32,
    0xedfbfb16_u32,
    0x864343c5_u32,
    0x9a4d4dd7_u32,
    0x66333355_u32,
    0x11858594_u32,
    0x8a4545cf_u32,
    0xe9f9f910_u32,
    0x04020206_u32,
    0xfe7f7f81_u32,
    0xa05050f0_u32,
    0x783c3c44_u32,
    0x259f9fba_u32,
    0x4ba8a8e3_u32,
    0xa25151f3_u32,
    0x5da3a3fe_u32,
    0x804040c0_u32,
    0x058f8f8a_u32,
    0x3f9292ad_u32,
    0x219d9dbc_u32,
    0x70383848_u32,
    0xf1f5f504_u32,
    0x63bcbcdf_u32,
    0x77b6b6c1_u32,
    0xafdada75_u32,
    0x42212163_u32,
    0x20101030_u32,
    0xe5ffff1a_u32,
    0xfdf3f30e_u32,
    0xbfd2d26d_u32,
    0x81cdcd4c_u32,
    0x180c0c14_u32,
    0x26131335_u32,
    0xc3ecec2f_u32,
    0xbe5f5fe1_u32,
    0x359797a2_u32,
    0x884444cc_u32,
    0x2e171739_u32,
    0x93c4c457_u32,
    0x55a7a7f2_u32,
    0xfc7e7e82_u32,
    0x7a3d3d47_u32,
    0xc86464ac_u32,
    0xba5d5de7_u32,
    0x3219192b_u32,
    0xe6737395_u32,
    0xc06060a0_u32,
    0x19818198_u32,
    0x9e4f4fd1_u32,
    0xa3dcdc7f_u32,
    0x44222266_u32,
    0x542a2a7e_u32,
    0x3b9090ab_u32,
    0x0b888883_u32,
    0x8c4646ca_u32,
    0xc7eeee29_u32,
    0x6bb8b8d3_u32,
    0x2814143c_u32,
    0xa7dede79_u32,
    0xbc5e5ee2_u32,
    0x160b0b1d_u32,
    0xaddbdb76_u32,
    0xdbe0e03b_u32,
    0x64323256_u32,
    0x743a3a4e_u32,
    0x140a0a1e_u32,
    0x924949db_u32,
    0x0c06060a_u32,
    0x4824246c_u32,
    0xb85c5ce4_u32,
    0x9fc2c25d_u32,
    0xbdd3d36e_u32,
    0x43acacef_u32,
    0xc46262a6_u32,
    0x399191a8_u32,
    0x319595a4_u32,
    0xd3e4e437_u32,
    0xf279798b_u32,
    0xd5e7e732_u32,
    0x8bc8c843_u32,
    0x6e373759_u32,
    0xda6d6db7_u32,
    0x018d8d8c_u32,
    0xb1d5d564_u32,
    0x9c4e4ed2_u32,
    0x49a9a9e0_u32,
    0xd86c6cb4_u32,
    0xac5656fa_u32,
    0xf3f4f407_u32,
    0xcfeaea25_u32,
    0xca6565af_u32,
    0xf47a7a8e_u32,
    0x47aeaee9_u32,
    0x10080818_u32,
    0x6fbabad5_u32,
    0xf0787888_u32,
    0x4a25256f_u32,
    0x5c2e2e72_u32,
    0x381c1c24_u32,
    0x57a6a6f1_u32,
    0x73b4b4c7_u32,
    0x97c6c651_u32,
    0xcbe8e823_u32,
    0xa1dddd7c_u32,
    0xe874749c_u32,
    0x3e1f1f21_u32,
    0x964b4bdd_u32,
    0x61bdbddc_u32,
    0x0d8b8b86_u32,
    0x0f8a8a85_u32,
    0xe0707090_u32,
    0x7c3e3e42_u32,
    0x71b5b5c4_u32,
    0xcc6666aa_u32,
    0x904848d8_u32,
    0x06030305_u32,
    0xf7f6f601_u32,
    0x1c0e0e12_u32,
    0xc26161a3_u32,
    0x6a35355f_u32,
    0xae5757f9_u32,
    0x69b9b9d0_u32,
    0x17868691_u32,
    0x99c1c158_u32,
    0x3a1d1d27_u32,
    0x279e9eb9_u32,
    0xd9e1e138_u32,
    0xebf8f813_u32,
    0x2b9898b3_u32,
    0x22111133_u32,
    0xd26969bb_u32,
    0xa9d9d970_u32,
    0x078e8e89_u32,
    0x339494a7_u32,
    0x2d9b9bb6_u32,
    0x3c1e1e22_u32,
    0x15878792_u32,
    0xc9e9e920_u32,
    0x87cece49_u32,
    0xaa5555ff_u32,
    0x50282878_u32,
    0xa5dfdf7a_u32,
    0x038c8c8f_u32,
    0x59a1a1f8_u32,
    0x09898980_u32,
    0x1a0d0d17_u32,
    0x65bfbfda_u32,
    0xd7e6e631_u32,
    0x844242c6_u32,
    0xd06868b8_u32,
    0x824141c3_u32,
    0x299999b0_u32,
    0x5a2d2d77_u32,
    0x1e0f0f11_u32,
    0x7bb0b0cb_u32,
    0xa85454fc_u32,
    0x6dbbbbd6_u32,
    0x2c16163a_u32,
];

static TE1: [u32; 256] = [
    0xa5c66363_u32,
    0x84f87c7c_u32,
    0x99ee7777_u32,
    0x8df67b7b_u32,
    0x0dfff2f2_u32,
    0xbdd66b6b_u32,
    0xb1de6f6f_u32,
    0x5491c5c5_u32,
    0x50603030_u32,
    0x03020101_u32,
    0xa9ce6767_u32,
    0x7d562b2b_u32,
    0x19e7fefe_u32,
    0x62b5d7d7_u32,
    0xe64dabab_u32,
    0x9aec7676_u32,
    0x458fcaca_u32,
    0x9d1f8282_u32,
    0x4089c9c9_u32,
    0x87fa7d7d_u32,
    0x15effafa_u32,
    0xebb25959_u32,
    0xc98e4747_u32,
    0x0bfbf0f0_u32,
    0xec41adad_u32,
    0x67b3d4d4_u32,
    0xfd5fa2a2_u32,
    0xea45afaf_u32,
    0xbf239c9c_u32,
    0xf753a4a4_u32,
    0x96e47272_u32,
    0x5b9bc0c0_u32,
    0xc275b7b7_u32,
    0x1ce1fdfd_u32,
    0xae3d9393_u32,
    0x6a4c2626_u32,
    0x5a6c3636_u32,
    0x417e3f3f_u32,
    0x02f5f7f7_u32,
    0x4f83cccc_u32,
    0x5c683434_u32,
    0xf451a5a5_u32,
    0x34d1e5e5_u32,
    0x08f9f1f1_u32,
    0x93e27171_u32,
    0x73abd8d8_u32,
    0x53623131_u32,
    0x3f2a1515_u32,
    0x0c080404_u32,
    0x5295c7c7_u32,
    0x65462323_u32,
    0x5e9dc3c3_u32,
    0x28301818_u32,
    0xa1379696_u32,
    0x0f0a0505_u32,
    0xb52f9a9a_u32,
    0x090e0707_u32,
    0x36241212_u32,
    0x9b1b8080_u32,
    0x3ddfe2e2_u32,
    0x26cdebeb_u32,
    0x694e2727_u32,
    0xcd7fb2b2_u32,
    0x9fea7575_u32,
    0x1b120909_u32,
    0x9e1d8383_u32,
    0x74582c2c_u32,
    0x2e341a1a_u32,
    0x2d361b1b_u32,
    0xb2dc6e6e_u32,
    0xeeb45a5a_u32,
    0xfb5ba0a0_u32,
    0xf6a45252_u32,
    0x4d763b3b_u32,
    0x61b7d6d6_u32,
    0xce7db3b3_u32,
    0x7b522929_u32,
    0x3edde3e3_u32,
    0x715e2f2f_u32,
    0x97138484_u32,
    0xf5a65353_u32,
    0x68b9d1d1_u32,
    0x00000000_u32,
    0x2cc1eded_u32,
    0x60402020_u32,
    0x1fe3fcfc_u32,
    0xc879b1b1_u32,
    0xedb65b5b_u32,
    0xbed46a6a_u32,
    0x468dcbcb_u32,
    0xd967bebe_u32,
    0x4b723939_u32,
    0xde944a4a_u32,
    0xd4984c4c_u32,
    0xe8b05858_u32,
    0x4a85cfcf_u32,
    0x6bbbd0d0_u32,
    0x2ac5efef_u32,
    0xe54faaaa_u32,
    0x16edfbfb_u32,
    0xc5864343_u32,
    0xd79a4d4d_u32,
    0x55663333_u32,
    0x94118585_u32,
    0xcf8a4545_u32,
    0x10e9f9f9_u32,
    0x06040202_u32,
    0x81fe7f7f_u32,
    0xf0a05050_u32,
    0x44783c3c_u32,
    0xba259f9f_u32,
    0xe34ba8a8_u32,
    0xf3a25151_u32,
    0xfe5da3a3_u32,
    0xc0804040_u32,
    0x8a058f8f_u32,
    0xad3f9292_u32,
    0xbc219d9d_u32,
    0x48703838_u32,
    0x04f1f5f5_u32,
    0xdf63bcbc_u32,
    0xc177b6b6_u32,
    0x75afdada_u32,
    0x63422121_u32,
    0x30201010_u32,
    0x1ae5ffff_u32,
    0x0efdf3f3_u32,
    0x6dbfd2d2_u32,
    0x4c81cdcd_u32,
    0x14180c0c_u32,
    0x35261313_u32,
    0x2fc3ecec_u32,
    0xe1be5f5f_u32,
    0xa2359797_u32,
    0xcc884444_u32,
    0x392e1717_u32,
    0x5793c4c4_u32,
    0xf255a7a7_u32,
    0x82fc7e7e_u32,
    0x477a3d3d_u32,
    0xacc86464_u32,
    0xe7ba5d5d_u32,
    0x2b321919_u32,
    0x95e67373_u32,
    0xa0c06060_u32,
    0x98198181_u32,
    0xd19e4f4f_u32,
    0x7fa3dcdc_u32,
    0x66442222_u32,
    0x7e542a2a_u32,
    0xab3b9090_u32,
    0x830b8888_u32,
    0xca8c4646_u32,
    0x29c7eeee_u32,
    0xd36bb8b8_u32,
    0x3c281414_u32,
    0x79a7dede_u32,
    0xe2bc5e5e_u32,
    0x1d160b0b_u32,
    0x76addbdb_u32,
    0x3bdbe0e0_u32,
    0x56643232_u32,
    0x4e743a3a_u32,
    0x1e140a0a_u32,
    0xdb924949_u32,
    0x0a0c0606_u32,
    0x6c482424_u32,
    0xe4b85c5c_u32,
    0x5d9fc2c2_u32,
    0x6ebdd3d3_u32,
    0xef43acac_u32,
    0xa6c46262_u32,
    0xa8399191_u32,
    0xa4319595_u32,
    0x37d3e4e4_u32,
    0x8bf27979_u32,
    0x32d5e7e7_u32,
    0x438bc8c8_u32,
    0x596e3737_u32,
    0xb7da6d6d_u32,
    0x8c018d8d_u32,
    0x64b1d5d5_u32,
    0xd29c4e4e_u32,
    0xe049a9a9_u32,
    0xb4d86c6c_u32,
    0xfaac5656_u32,
    0x07f3f4f4_u32,
    0x25cfeaea_u32,
    0xafca6565_u32,
    0x8ef47a7a_u32,
    0xe947aeae_u32,
    0x18100808_u32,
    0xd56fbaba_u32,
    0x88f07878_u32,
    0x6f4a2525_u32,
    0x725c2e2e_u32,
    0x24381c1c_u32,
    0xf157a6a6_u32,
    0xc773b4b4_u32,
    0x5197c6c6_u32,
    0x23cbe8e8_u32,
    0x7ca1dddd_u32,
    0x9ce87474_u32,
    0x213e1f1f_u32,
    0xdd964b4b_u32,
    0xdc61bdbd_u32,
    0x860d8b8b_u32,
    0x850f8a8a_u32,
    0x90e07070_u32,
    0x427c3e3e_u32,
    0xc471b5b5_u32,
    0xaacc6666_u32,
    0xd8904848_u32,
    0x05060303_u32,
    0x01f7f6f6_u32,
    0x121c0e0e_u32,
    0xa3c26161_u32,
    0x5f6a3535_u32,
    0xf9ae5757_u32,
    0xd069b9b9_u32,
    0x91178686_u32,
    0x5899c1c1_u32,
    0x273a1d1d_u32,
    0xb9279e9e_u32,
    0x38d9e1e1_u32,
    0x13ebf8f8_u32,
    0xb32b9898_u32,
    0x33221111_u32,
    0xbbd26969_u32,
    0x70a9d9d9_u32,
    0x89078e8e_u32,
    0xa7339494_u32,
    0xb62d9b9b_u32,
    0x223c1e1e_u32,
    0x92158787_u32,
    0x20c9e9e9_u32,
    0x4987cece_u32,
    0xffaa5555_u32,
    0x78502828_u32,
    0x7aa5dfdf_u32,
    0x8f038c8c_u32,
    0xf859a1a1_u32,
    0x80098989_u32,
    0x171a0d0d_u32,
    0xda65bfbf_u32,
    0x31d7e6e6_u32,
    0xc6844242_u32,
    0xb8d06868_u32,
    0xc3824141_u32,
    0xb0299999_u32,
    0x775a2d2d_u32,
    0x111e0f0f_u32,
    0xcb7bb0b0_u32,
    0xfca85454_u32,
    0xd66dbbbb_u32,
    0x3a2c1616_u32,
];

static TE2: [u32; 256] = [
    0x63a5c663_u32,
    0x7c84f87c_u32,
    0x7799ee77_u32,
    0x7b8df67b_u32,
    0xf20dfff2_u32,
    0x6bbdd66b_u32,
    0x6fb1de6f_u32,
    0xc55491c5_u32,
    0x30506030_u32,
    0x01030201_u32,
    0x67a9ce67_u32,
    0x2b7d562b_u32,
    0xfe19e7fe_u32,
    0xd762b5d7_u32,
    0xabe64dab_u32,
    0x769aec76_u32,
    0xca458fca_u32,
    0x829d1f82_u32,
    0xc94089c9_u32,
    0x7d87fa7d_u32,
    0xfa15effa_u32,
    0x59ebb259_u32,
    0x47c98e47_u32,
    0xf00bfbf0_u32,
    0xadec41ad_u32,
    0xd467b3d4_u32,
    0xa2fd5fa2_u32,
    0xafea45af_u32,
    0x9cbf239c_u32,
    0xa4f753a4_u32,
    0x7296e472_u32,
    0xc05b9bc0_u32,
    0xb7c275b7_u32,
    0xfd1ce1fd_u32,
    0x93ae3d93_u32,
    0x266a4c26_u32,
    0x365a6c36_u32,
    0x3f417e3f_u32,
    0xf702f5f7_u32,
    0xcc4f83cc_u32,
    0x345c6834_u32,
    0xa5f451a5_u32,
    0xe534d1e5_u32,
    0xf108f9f1_u32,
    0x7193e271_u32,
    0xd873abd8_u32,
    0x31536231_u32,
    0x153f2a15_u32,
    0x040c0804_u32,
    0xc75295c7_u32,
    0x23654623_u32,
    0xc35e9dc3_u32,
    0x18283018_u32,
    0x96a13796_u32,
    0x050f0a05_u32,
    0x9ab52f9a_u32,
    0x07090e07_u32,
    0x12362412_u32,
    0x809b1b80_u32,
    0xe23ddfe2_u32,
    0xeb26cdeb_u32,
    0x27694e27_u32,
    0xb2cd7fb2_u32,
    0x759fea75_u32,
    0x091b1209_u32,
    0x839e1d83_u32,
    0x2c74582c_u32,
    0x1a2e341a_u32,
    0x1b2d361b_u32,
    0x6eb2dc6e_u32,
    0x5aeeb45a_u32,
    0xa0fb5ba0_u32,
    0x52f6a452_u32,
    0x3b4d763b_u32,
    0xd661b7d6_u32,
    0xb3ce7db3_u32,
    0x297b5229_u32,
    0xe33edde3_u32,
    0x2f715e2f_u32,
    0x84971384_u32,
    0x53f5a653_u32,
    0xd168b9d1_u32,
    0x00000000_u32,
    0xed2cc1ed_u32,
    0x20604020_u32,
    0xfc1fe3fc_u32,
    0xb1c879b1_u32,
    0x5bedb65b_u32,
    0x6abed46a_u32,
    0xcb468dcb_u32,
    0xbed967be_u32,
    0x394b7239_u32,
    0x4ade944a_u32,
    0x4cd4984c_u32,
    0x58e8b058_u32,
    0xcf4a85cf_u32,
    0xd06bbbd0_u32,
    0xef2ac5ef_u32,
    0xaae54faa_u32,
    0xfb16edfb_u32,
    0x43c58643_u32,
    0x4dd79a4d_u32,
    0x33556633_u32,
    0x85941185_u32,
    0x45cf8a45_u32,
    0xf910e9f9_u32,
    0x02060402_u32,
    0x7f81fe7f_u32,
    0x50f0a050_u32,
    0x3c44783c_u32,
    0x9fba259f_u32,
    0xa8e34ba8_u32,
    0x51f3a251_u32,
    0xa3fe5da3_u32,
    0x40c08040_u32,
    0x8f8a058f_u32,
    0x92ad3f92_u32,
    0x9dbc219d_u32,
    0x38487038_u32,
    0xf504f1f5_u32,
    0xbcdf63bc_u32,
    0xb6c177b6_u32,
    0xda75afda_u32,
    0x21634221_u32,
    0x10302010_u32,
    0xff1ae5ff_u32,
    0xf30efdf3_u32,
    0xd26dbfd2_u32,
    0xcd4c81cd_u32,
    0x0c14180c_u32,
    0x13352613_u32,
    0xec2fc3ec_u32,
    0x5fe1be5f_u32,
    0x97a23597_u32,
    0x44cc8844_u32,
    0x17392e17_u32,
    0xc45793c4_u32,
    0xa7f255a7_u32,
    0x7e82fc7e_u32,
    0x3d477a3d_u32,
    0x64acc864_u32,
    0x5de7ba5d_u32,
    0x192b3219_u32,
    0x7395e673_u32,
    0x60a0c060_u32,
    0x81981981_u32,
    0x4fd19e4f_u32,
    0xdc7fa3dc_u32,
    0x22664422_u32,
    0x2a7e542a_u32,
    0x90ab3b90_u32,
    0x88830b88_u32,
    0x46ca8c46_u32,
    0xee29c7ee_u32,
    0xb8d36bb8_u32,
    0x143c2814_u32,
    0xde79a7de_u32,
    0x5ee2bc5e_u32,
    0x0b1d160b_u32,
    0xdb76addb_u32,
    0xe03bdbe0_u32,
    0x32566432_u32,
    0x3a4e743a_u32,
    0x0a1e140a_u32,
    0x49db9249_u32,
    0x060a0c06_u32,
    0x246c4824_u32,
    0x5ce4b85c_u32,
    0xc25d9fc2_u32,
    0xd36ebdd3_u32,
    0xacef43ac_u32,
    0x62a6c462_u32,
    0x91a83991_u32,
    0x95a43195_u32,
    0xe437d3e4_u32,
    0x798bf279_u32,
    0xe732d5e7_u32,
    0xc8438bc8_u32,
    0x37596e37_u32,
    0x6db7da6d_u32,
    0x8d8c018d_u32,
    0xd564b1d5_u32,
    0x4ed29c4e_u32,
    0xa9e049a9_u32,
    0x6cb4d86c_u32,
    0x56faac56_u32,
    0xf407f3f4_u32,
    0xea25cfea_u32,
    0x65afca65_u32,
    0x7a8ef47a_u32,
    0xaee947ae_u32,
    0x08181008_u32,
    0xbad56fba_u32,
    0x7888f078_u32,
    0x256f4a25_u32,
    0x2e725c2e_u32,
    0x1c24381c_u32,
    0xa6f157a6_u32,
    0xb4c773b4_u32,
    0xc65197c6_u32,
    0xe823cbe8_u32,
    0xdd7ca1dd_u32,
    0x749ce874_u32,
    0x1f213e1f_u32,
    0x4bdd964b_u32,
    0xbddc61bd_u32,
    0x8b860d8b_u32,
    0x8a850f8a_u32,
    0x7090e070_u32,
    0x3e427c3e_u32,
    0xb5c471b5_u32,
    0x66aacc66_u32,
    0x48d89048_u32,
    0x03050603_u32,
    0xf601f7f6_u32,
    0x0e121c0e_u32,
    0x61a3c261_u32,
    0x355f6a35_u32,
    0x57f9ae57_u32,
    0xb9d069b9_u32,
    0x86911786_u32,
    0xc15899c1_u32,
    0x1d273a1d_u32,
    0x9eb9279e_u32,
    0xe138d9e1_u32,
    0xf813ebf8_u32,
    0x98b32b98_u32,
    0x11332211_u32,
    0x69bbd269_u32,
    0xd970a9d9_u32,
    0x8e89078e_u32,
    0x94a73394_u32,
    0x9bb62d9b_u32,
    0x1e223c1e_u32,
    0x87921587_u32,
    0xe920c9e9_u32,
    0xce4987ce_u32,
    0x55ffaa55_u32,
    0x28785028_u32,
    0xdf7aa5df_u32,
    0x8c8f038c_u32,
    0xa1f859a1_u32,
    0x89800989_u32,
    0x0d171a0d_u32,
    0xbfda65bf_u32,
    0xe631d7e6_u32,
    0x42c68442_u32,
    0x68b8d068_u32,
    0x41c38241_u32,
    0x99b02999_u32,
    0x2d775a2d_u32,
    0x0f111e0f_u32,
    0xb0cb7bb0_u32,
    0x54fca854_u32,
    0xbbd66dbb_u32,
    0x163a2c16_u32,
];

static TE3: [u32; 256] = [
    0x6363a5c6_u32,
    0x7c7c84f8_u32,
    0x777799ee_u32,
    0x7b7b8df6_u32,
    0xf2f20dff_u32,
    0x6b6bbdd6_u32,
    0x6f6fb1de_u32,
    0xc5c55491_u32,
    0x30305060_u32,
    0x01010302_u32,
    0x6767a9ce_u32,
    0x2b2b7d56_u32,
    0xfefe19e7_u32,
    0xd7d762b5_u32,
    0xababe64d_u32,
    0x76769aec_u32,
    0xcaca458f_u32,
    0x82829d1f_u32,
    0xc9c94089_u32,
    0x7d7d87fa_u32,
    0xfafa15ef_u32,
    0x5959ebb2_u32,
    0x4747c98e_u32,
    0xf0f00bfb_u32,
    0xadadec41_u32,
    0xd4d467b3_u32,
    0xa2a2fd5f_u32,
    0xafafea45_u32,
    0x9c9cbf23_u32,
    0xa4a4f753_u32,
    0x727296e4_u32,
    0xc0c05b9b_u32,
    0xb7b7c275_u32,
    0xfdfd1ce1_u32,
    0x9393ae3d_u32,
    0x26266a4c_u32,
    0x36365a6c_u32,
    0x3f3f417e_u32,
    0xf7f702f5_u32,
    0xcccc4f83_u32,
    0x34345c68_u32,
    0xa5a5f451_u32,
    0xe5e534d1_u32,
    0xf1f108f9_u32,
    0x717193e2_u32,
    0xd8d873ab_u32,
    0x31315362_u32,
    0x15153f2a_u32,
    0x04040c08_u32,
    0xc7c75295_u32,
    0x23236546_u32,
    0xc3c35e9d_u32,
    0x18182830_u32,
    0x9696a137_u32,
    0x05050f0a_u32,
    0x9a9ab52f_u32,
    0x0707090e_u32,
    0x12123624_u32,
    0x80809b1b_u32,
    0xe2e23ddf_u32,
    0xebeb26cd_u32,
    0x2727694e_u32,
    0xb2b2cd7f_u32,
    0x75759fea_u32,
    0x09091b12_u32,
    0x83839e1d_u32,
    0x2c2c7458_u32,
    0x1a1a2e34_u32,
    0x1b1b2d36_u32,
    0x6e6eb2dc_u32,
    0x5a5aeeb4_u32,
    0xa0a0fb5b_u32,
    0x5252f6a4_u32,
    0x3b3b4d76_u32,
    0xd6d661b7_u32,
    0xb3b3ce7d_u32,
    0x29297b52_u32,
    0xe3e33edd_u32,
    0x2f2f715e_u32,
    0x84849713_u32,
    0x5353f5a6_u32,
    0xd1d168b9_u32,
    0x00000000_u32,
    0xeded2cc1_u32,
    0x20206040_u32,
    0xfcfc1fe3_u32,
    0xb1b1c879_u32,
    0x5b5bedb6_u32,
    0x6a6abed4_u32,
    0xcbcb468d_u32,
    0xbebed967_u32,
    0x39394b72_u32,
    0x4a4ade94_u32,
    0x4c4cd498_u32,
    0x5858e8b0_u32,
    0xcfcf4a85_u32,
    0xd0d06bbb_u32,
    0xefef2ac5_u32,
    0xaaaae54f_u32,
    0xfbfb16ed_u32,
    0x4343c586_u32,
    0x4d4dd79a_u32,
    0x33335566_u32,
    0x85859411_u32,
    0x4545cf8a_u32,
    0xf9f910e9_u32,
    0x02020604_u32,
    0x7f7f81fe_u32,
    0x5050f0a0_u32,
    0x3c3c4478_u32,
    0x9f9fba25_u32,
    0xa8a8e34b_u32,
    0x5151f3a2_u32,
    0xa3a3fe5d_u32,
    0x4040c080_u32,
    0x8f8f8a05_u32,
    0x9292ad3f_u32,
    0x9d9dbc21_u32,
    0x38384870_u32,
    0xf5f504f1_u32,
    0xbcbcdf63_u32,
    0xb6b6c177_u32,
    0xdada75af_u32,
    0x21216342_u32,
    0x10103020_u32,
    0xffff1ae5_u32,
    0xf3f30efd_u32,
    0xd2d26dbf_u32,
    0xcdcd4c81_u32,
    0x0c0c1418_u32,
    0x13133526_u32,
    0xecec2fc3_u32,
    0x5f5fe1be_u32,
    0x9797a235_u32,
    0x4444cc88_u32,
    0x1717392e_u32,
    0xc4c45793_u32,
    0xa7a7f255_u32,
    0x7e7e82fc_u32,
    0x3d3d477a_u32,
    0x6464acc8_u32,
    0x5d5de7ba_u32,
    0x19192b32_u32,
    0x737395e6_u32,
    0x6060a0c0_u32,
    0x81819819_u32,
    0x4f4fd19e_u32,
    0xdcdc7fa3_u32,
    0x22226644_u32,
    0x2a2a7e54_u32,
    0x9090ab3b_u32,
    0x8888830b_u32,
    0x4646ca8c_u32,
    0xeeee29c7_u32,
    0xb8b8d36b_u32,
    0x14143c28_u32,
    0xdede79a7_u32,
    0x5e5ee2bc_u32,
    0x0b0b1d16_u32,
    0xdbdb76ad_u32,
    0xe0e03bdb_u32,
    0x32325664_u32,
    0x3a3a4e74_u32,
    0x0a0a1e14_u32,
    0x4949db92_u32,
    0x06060a0c_u32,
    0x24246c48_u32,
    0x5c5ce4b8_u32,
    0xc2c25d9f_u32,
    0xd3d36ebd_u32,
    0xacacef43_u32,
    0x6262a6c4_u32,
    0x9191a839_u32,
    0x9595a431_u32,
    0xe4e437d3_u32,
    0x79798bf2_u32,
    0xe7e732d5_u32,
    0xc8c8438b_u32,
    0x3737596e_u32,
    0x6d6db7da_u32,
    0x8d8d8c01_u32,
    0xd5d564b1_u32,
    0x4e4ed29c_u32,
    0xa9a9e049_u32,
    0x6c6cb4d8_u32,
    0x5656faac_u32,
    0xf4f407f3_u32,
    0xeaea25cf_u32,
    0x6565afca_u32,
    0x7a7a8ef4_u32,
    0xaeaee947_u32,
    0x08081810_u32,
    0xbabad56f_u32,
    0x787888f0_u32,
    0x25256f4a_u32,
    0x2e2e725c_u32,
    0x1c1c2438_u32,
    0xa6a6f157_u32,
    0xb4b4c773_u32,
    0xc6c65197_u32,
    0xe8e823cb_u32,
    0xdddd7ca1_u32,
    0x74749ce8_u32,
    0x1f1f213e_u32,
    0x4b4bdd96_u32,
    0xbdbddc61_u32,
    0x8b8b860d_u32,
    0x8a8a850f_u32,
    0x707090e0_u32,
    0x3e3e427c_u32,
    0xb5b5c471_u32,
    0x6666aacc_u32,
    0x4848d890_u32,
    0x03030506_u32,
    0xf6f601f7_u32,
    0x0e0e121c_u32,
    0x6161a3c2_u32,
    0x35355f6a_u32,
    0x5757f9ae_u32,
    0xb9b9d069_u32,
    0x86869117_u32,
    0xc1c15899_u32,
    0x1d1d273a_u32,
    0x9e9eb927_u32,
    0xe1e138d9_u32,
    0xf8f813eb_u32,
    0x9898b32b_u32,
    0x11113322_u32,
    0x6969bbd2_u32,
    0xd9d970a9_u32,
    0x8e8e8907_u32,
    0x9494a733_u32,
    0x9b9bb62d_u32,
    0x1e1e223c_u32,
    0x87879215_u32,
    0xe9e920c9_u32,
    0xcece4987_u32,
    0x5555ffaa_u32,
    0x28287850_u32,
    0xdfdf7aa5_u32,
    0x8c8c8f03_u32,
    0xa1a1f859_u32,
    0x89898009_u32,
    0x0d0d171a_u32,
    0xbfbfda65_u32,
    0xe6e631d7_u32,
    0x4242c684_u32,
    0x6868b8d0_u32,
    0x4141c382_u32,
    0x9999b029_u32,
    0x2d2d775a_u32,
    0x0f0f111e_u32,
    0xb0b0cb7b_u32,
    0x5454fca8_u32,
    0xbbbbd66d_u32,
    0x16163a2c_u32,
];

static TE4: [u32; 256] = [
    0x63636363_u32,
    0x7c7c7c7c_u32,
    0x77777777_u32,
    0x7b7b7b7b_u32,
    0xf2f2f2f2_u32,
    0x6b6b6b6b_u32,
    0x6f6f6f6f_u32,
    0xc5c5c5c5_u32,
    0x30303030_u32,
    0x01010101_u32,
    0x67676767_u32,
    0x2b2b2b2b_u32,
    0xfefefefe_u32,
    0xd7d7d7d7_u32,
    0xabababab_u32,
    0x76767676_u32,
    0xcacacaca_u32,
    0x82828282_u32,
    0xc9c9c9c9_u32,
    0x7d7d7d7d_u32,
    0xfafafafa_u32,
    0x59595959_u32,
    0x47474747_u32,
    0xf0f0f0f0_u32,
    0xadadadad_u32,
    0xd4d4d4d4_u32,
    0xa2a2a2a2_u32,
    0xafafafaf_u32,
    0x9c9c9c9c_u32,
    0xa4a4a4a4_u32,
    0x72727272_u32,
    0xc0c0c0c0_u32,
    0xb7b7b7b7_u32,
    0xfdfdfdfd_u32,
    0x93939393_u32,
    0x26262626_u32,
    0x36363636_u32,
    0x3f3f3f3f_u32,
    0xf7f7f7f7_u32,
    0xcccccccc_u32,
    0x34343434_u32,
    0xa5a5a5a5_u32,
    0xe5e5e5e5_u32,
    0xf1f1f1f1_u32,
    0x71717171_u32,
    0xd8d8d8d8_u32,
    0x31313131_u32,
    0x15151515_u32,
    0x04040404_u32,
    0xc7c7c7c7_u32,
    0x23232323_u32,
    0xc3c3c3c3_u32,
    0x18181818_u32,
    0x96969696_u32,
    0x05050505_u32,
    0x9a9a9a9a_u32,
    0x07070707_u32,
    0x12121212_u32,
    0x80808080_u32,
    0xe2e2e2e2_u32,
    0xebebebeb_u32,
    0x27272727_u32,
    0xb2b2b2b2_u32,
    0x75757575_u32,
    0x09090909_u32,
    0x83838383_u32,
    0x2c2c2c2c_u32,
    0x1a1a1a1a_u32,
    0x1b1b1b1b_u32,
    0x6e6e6e6e_u32,
    0x5a5a5a5a_u32,
    0xa0a0a0a0_u32,
    0x52525252_u32,
    0x3b3b3b3b_u32,
    0xd6d6d6d6_u32,
    0xb3b3b3b3_u32,
    0x29292929_u32,
    0xe3e3e3e3_u32,
    0x2f2f2f2f_u32,
    0x84848484_u32,
    0x53535353_u32,
    0xd1d1d1d1_u32,
    0x00000000_u32,
    0xedededed_u32,
    0x20202020_u32,
    0xfcfcfcfc_u32,
    0xb1b1b1b1_u32,
    0x5b5b5b5b_u32,
    0x6a6a6a6a_u32,
    0xcbcbcbcb_u32,
    0xbebebebe_u32,
    0x39393939_u32,
    0x4a4a4a4a_u32,
    0x4c4c4c4c_u32,
    0x58585858_u32,
    0xcfcfcfcf_u32,
    0xd0d0d0d0_u32,
    0xefefefef_u32,
    0xaaaaaaaa_u32,
    0xfbfbfbfb_u32,
    0x43434343_u32,
    0x4d4d4d4d_u32,
    0x33333333_u32,
    0x85858585_u32,
    0x45454545_u32,
    0xf9f9f9f9_u32,
    0x02020202_u32,
    0x7f7f7f7f_u32,
    0x50505050_u32,
    0x3c3c3c3c_u32,
    0x9f9f9f9f_u32,
    0xa8a8a8a8_u32,
    0x51515151_u32,
    0xa3a3a3a3_u32,
    0x40404040_u32,
    0x8f8f8f8f_u32,
    0x92929292_u32,
    0x9d9d9d9d_u32,
    0x38383838_u32,
    0xf5f5f5f5_u32,
    0xbcbcbcbc_u32,
    0xb6b6b6b6_u32,
    0xdadadada_u32,
    0x21212121_u32,
    0x10101010_u32,
    0xffffffff_u32,
    0xf3f3f3f3_u32,
    0xd2d2d2d2_u32,
    0xcdcdcdcd_u32,
    0x0c0c0c0c_u32,
    0x13131313_u32,
    0xecececec_u32,
    0x5f5f5f5f_u32,
    0x97979797_u32,
    0x44444444_u32,
    0x17171717_u32,
    0xc4c4c4c4_u32,
    0xa7a7a7a7_u32,
    0x7e7e7e7e_u32,
    0x3d3d3d3d_u32,
    0x64646464_u32,
    0x5d5d5d5d_u32,
    0x19191919_u32,
    0x73737373_u32,
    0x60606060_u32,
    0x81818181_u32,
    0x4f4f4f4f_u32,
    0xdcdcdcdc_u32,
    0x22222222_u32,
    0x2a2a2a2a_u32,
    0x90909090_u32,
    0x88888888_u32,
    0x46464646_u32,
    0xeeeeeeee_u32,
    0xb8b8b8b8_u32,
    0x14141414_u32,
    0xdededede_u32,
    0x5e5e5e5e_u32,
    0x0b0b0b0b_u32,
    0xdbdbdbdb_u32,
    0xe0e0e0e0_u32,
    0x32323232_u32,
    0x3a3a3a3a_u32,
    0x0a0a0a0a_u32,
    0x49494949_u32,
    0x06060606_u32,
    0x24242424_u32,
    0x5c5c5c5c_u32,
    0xc2c2c2c2_u32,
    0xd3d3d3d3_u32,
    0xacacacac_u32,
    0x62626262_u32,
    0x91919191_u32,
    0x95959595_u32,
    0xe4e4e4e4_u32,
    0x79797979_u32,
    0xe7e7e7e7_u32,
    0xc8c8c8c8_u32,
    0x37373737_u32,
    0x6d6d6d6d_u32,
    0x8d8d8d8d_u32,
    0xd5d5d5d5_u32,
    0x4e4e4e4e_u32,
    0xa9a9a9a9_u32,
    0x6c6c6c6c_u32,
    0x56565656_u32,
    0xf4f4f4f4_u32,
    0xeaeaeaea_u32,
    0x65656565_u32,
    0x7a7a7a7a_u32,
    0xaeaeaeae_u32,
    0x08080808_u32,
    0xbabababa_u32,
    0x78787878_u32,
    0x25252525_u32,
    0x2e2e2e2e_u32,
    0x1c1c1c1c_u32,
    0xa6a6a6a6_u32,
    0xb4b4b4b4_u32,
    0xc6c6c6c6_u32,
    0xe8e8e8e8_u32,
    0xdddddddd_u32,
    0x74747474_u32,
    0x1f1f1f1f_u32,
    0x4b4b4b4b_u32,
    0xbdbdbdbd_u32,
    0x8b8b8b8b_u32,
    0x8a8a8a8a_u32,
    0x70707070_u32,
    0x3e3e3e3e_u32,
    0xb5b5b5b5_u32,
    0x66666666_u32,
    0x48484848_u32,
    0x03030303_u32,
    0xf6f6f6f6_u32,
    0x0e0e0e0e_u32,
    0x61616161_u32,
    0x35353535_u32,
    0x57575757_u32,
    0xb9b9b9b9_u32,
    0x86868686_u32,
    0xc1c1c1c1_u32,
    0x1d1d1d1d_u32,
    0x9e9e9e9e_u32,
    0xe1e1e1e1_u32,
    0xf8f8f8f8_u32,
    0x98989898_u32,
    0x11111111_u32,
    0x69696969_u32,
    0xd9d9d9d9_u32,
    0x8e8e8e8e_u32,
    0x94949494_u32,
    0x9b9b9b9b_u32,
    0x1e1e1e1e_u32,
    0x87878787_u32,
    0xe9e9e9e9_u32,
    0xcececece_u32,
    0x55555555_u32,
    0x28282828_u32,
    0xdfdfdfdf_u32,
    0x8c8c8c8c_u32,
    0xa1a1a1a1_u32,
    0x89898989_u32,
    0x0d0d0d0d_u32,
    0xbfbfbfbf_u32,
    0xe6e6e6e6_u32,
    0x42424242_u32,
    0x68686868_u32,
    0x41414141_u32,
    0x99999999_u32,
    0x2d2d2d2d_u32,
    0x0f0f0f0f_u32,
    0xb0b0b0b0_u32,
    0x54545454_u32,
    0xbbbbbbbb_u32,
    0x16161616_u32,
];

static TD0: [u32; 256] = [
    0x51f4a750_u32,
    0x7e416553_u32,
    0x1a17a4c3_u32,
    0x3a275e96_u32,
    0x3bab6bcb_u32,
    0x1f9d45f1_u32,
    0xacfa58ab_u32,
    0x4be30393_u32,
    0x2030fa55_u32,
    0xad766df6_u32,
    0x88cc7691_u32,
    0xf5024c25_u32,
    0x4fe5d7fc_u32,
    0xc52acbd7_u32,
    0x26354480_u32,
    0xb562a38f_u32,
    0xdeb15a49_u32,
    0x25ba1b67_u32,
    0x45ea0e98_u32,
    0x5dfec0e1_u32,
    0xc32f7502_u32,
    0x814cf012_u32,
    0x8d4697a3_u32,
    0x6bd3f9c6_u32,
    0x038f5fe7_u32,
    0x15929c95_u32,
    0xbf6d7aeb_u32,
    0x955259da_u32,
    0xd4be832d_u32,
    0x587421d3_u32,
    0x49e06929_u32,
    0x8ec9c844_u32,
    0x75c2896a_u32,
    0xf48e7978_u32,
    0x99583e6b_u32,
    0x27b971dd_u32,
    0xbee14fb6_u32,
    0xf088ad17_u32,
    0xc920ac66_u32,
    0x7dce3ab4_u32,
    0x63df4a18_u32,
    0xe51a3182_u32,
    0x97513360_u32,
    0x62537f45_u32,
    0xb16477e0_u32,
    0xbb6bae84_u32,
    0xfe81a01c_u32,
    0xf9082b94_u32,
    0x70486858_u32,
    0x8f45fd19_u32,
    0x94de6c87_u32,
    0x527bf8b7_u32,
    0xab73d323_u32,
    0x724b02e2_u32,
    0xe31f8f57_u32,
    0x6655ab2a_u32,
    0xb2eb2807_u32,
    0x2fb5c203_u32,
    0x86c57b9a_u32,
    0xd33708a5_u32,
    0x302887f2_u32,
    0x23bfa5b2_u32,
    0x02036aba_u32,
    0xed16825c_u32,
    0x8acf1c2b_u32,
    0xa779b492_u32,
    0xf307f2f0_u32,
    0x4e69e2a1_u32,
    0x65daf4cd_u32,
    0x0605bed5_u32,
    0xd134621f_u32,
    0xc4a6fe8a_u32,
    0x342e539d_u32,
    0xa2f355a0_u32,
    0x058ae132_u32,
    0xa4f6eb75_u32,
    0x0b83ec39_u32,
    0x4060efaa_u32,
    0x5e719f06_u32,
    0xbd6e1051_u32,
    0x3e218af9_u32,
    0x96dd063d_u32,
    0xdd3e05ae_u32,
    0x4de6bd46_u32,
    0x91548db5_u32,
    0x71c45d05_u32,
    0x0406d46f_u32,
    0x605015ff_u32,
    0x1998fb24_u32,
    0xd6bde997_u32,
    0x894043cc_u32,
    0x67d99e77_u32,
    0xb0e842bd_u32,
    0x07898b88_u32,
    0xe7195b38_u32,
    0x79c8eedb_u32,
    0xa17c0a47_u32,
    0x7c420fe9_u32,
    0xf8841ec9_u32,
    0x00000000_u32,
    0x09808683_u32,
    0x322bed48_u32,
    0x1e1170ac_u32,
    0x6c5a724e_u32,
    0xfd0efffb_u32,
    0x0f853856_u32,
    0x3daed51e_u32,
    0x362d3927_u32,
    0x0a0fd964_u32,
    0x685ca621_u32,
    0x9b5b54d1_u32,
    0x24362e3a_u32,
    0x0c0a67b1_u32,
    0x9357e70f_u32,
    0xb4ee96d2_u32,
    0x1b9b919e_u32,
    0x80c0c54f_u32,
    0x61dc20a2_u32,
    0x5a774b69_u32,
    0x1c121a16_u32,
    0xe293ba0a_u32,
    0xc0a02ae5_u32,
    0x3c22e043_u32,
    0x121b171d_u32,
    0x0e090d0b_u32,
    0xf28bc7ad_u32,
    0x2db6a8b9_u32,
    0x141ea9c8_u32,
    0x57f11985_u32,
    0xaf75074c_u32,
    0xee99ddbb_u32,
    0xa37f60fd_u32,
    0xf701269f_u32,
    0x5c72f5bc_u32,
    0x44663bc5_u32,
    0x5bfb7e34_u32,
    0x8b432976_u32,
    0xcb23c6dc_u32,
    0xb6edfc68_u32,
    0xb8e4f163_u32,
    0xd731dcca_u32,
    0x42638510_u32,
    0x13972240_u32,
    0x84c61120_u32,
    0x854a247d_u32,
    0xd2bb3df8_u32,
    0xaef93211_u32,
    0xc729a16d_u32,
    0x1d9e2f4b_u32,
    0xdcb230f3_u32,
    0x0d8652ec_u32,
    0x77c1e3d0_u32,
    0x2bb3166c_u32,
    0xa970b999_u32,
    0x119448fa_u32,
    0x47e96422_u32,
    0xa8fc8cc4_u32,
    0xa0f03f1a_u32,
    0x567d2cd8_u32,
    0x223390ef_u32,
    0x87494ec7_u32,
    0xd938d1c1_u32,
    0x8ccaa2fe_u32,
    0x98d40b36_u32,
    0xa6f581cf_u32,
    0xa57ade28_u32,
    0xdab78e26_u32,
    0x3fadbfa4_u32,
    0x2c3a9de4_u32,
    0x5078920d_u32,
    0x6a5fcc9b_u32,
    0x547e4662_u32,
    0xf68d13c2_u32,
    0x90d8b8e8_u32,
    0x2e39f75e_u32,
    0x82c3aff5_u32,
    0x9f5d80be_u32,
    0x69d0937c_u32,
    0x6fd52da9_u32,
    0xcf2512b3_u32,
    0xc8ac993b_u32,
    0x10187da7_u32,
    0xe89c636e_u32,
    0xdb3bbb7b_u32,
    0xcd267809_u32,
    0x6e5918f4_u32,
    0xec9ab701_u32,
    0x834f9aa8_u32,
    0xe6956e65_u32,
    0xaaffe67e_u32,
    0x21bccf08_u32,
    0xef15e8e6_u32,
    0xbae79bd9_u32,
    0x4a6f36ce_u32,
    0xea9f09d4_u32,
    0x29b07cd6_u32,
    0x31a4b2af_u32,
    0x2a3f2331_u32,
    0xc6a59430_u32,
    0x35a266c0_u32,
    0x744ebc37_u32,
    0xfc82caa6_u32,
    0xe090d0b0_u32,
    0x33a7d815_u32,
    0xf104984a_u32,
    0x41ecdaf7_u32,
    0x7fcd500e_u32,
    0x1791f62f_u32,
    0x764dd68d_u32,
    0x43efb04d_u32,
    0xccaa4d54_u32,
    0xe49604df_u32,
    0x9ed1b5e3_u32,
    0x4c6a881b_u32,
    0xc12c1fb8_u32,
    0x4665517f_u32,
    0x9d5eea04_u32,
    0x018c355d_u32,
    0xfa877473_u32,
    0xfb0b412e_u32,
    0xb3671d5a_u32,
    0x92dbd252_u32,
    0xe9105633_u32,
    0x6dd64713_u32,
    0x9ad7618c_u32,
    0x37a10c7a_u32,
    0x59f8148e_u32,
    0xeb133c89_u32,
    0xcea927ee_u32,
    0xb761c935_u32,
    0xe11ce5ed_u32,
    0x7a47b13c_u32,
    0x9cd2df59_u32,
    0x55f2733f_u32,
    0x1814ce79_u32,
    0x73c737bf_u32,
    0x53f7cdea_u32,
    0x5ffdaa5b_u32,
    0xdf3d6f14_u32,
    0x7844db86_u32,
    0xcaaff381_u32,
    0xb968c43e_u32,
    0x3824342c_u32,
    0xc2a3405f_u32,
    0x161dc372_u32,
    0xbce2250c_u32,
    0x283c498b_u32,
    0xff0d9541_u32,
    0x39a80171_u32,
    0x080cb3de_u32,
    0xd8b4e49c_u32,
    0x6456c190_u32,
    0x7bcb8461_u32,
    0xd532b670_u32,
    0x486c5c74_u32,
    0xd0b85742_u32,
];

static TD1: [u32; 256] = [
    0x5051f4a7_u32,
    0x537e4165_u32,
    0xc31a17a4_u32,
    0x963a275e_u32,
    0xcb3bab6b_u32,
    0xf11f9d45_u32,
    0xabacfa58_u32,
    0x934be303_u32,
    0x552030fa_u32,
    0xf6ad766d_u32,
    0x9188cc76_u32,
    0x25f5024c_u32,
    0xfc4fe5d7_u32,
    0xd7c52acb_u32,
    0x80263544_u32,
    0x8fb562a3_u32,
    0x49deb15a_u32,
    0x6725ba1b_u32,
    0x9845ea0e_u32,
    0xe15dfec0_u32,
    0x02c32f75_u32,
    0x12814cf0_u32,
    0xa38d4697_u32,
    0xc66bd3f9_u32,
    0xe7038f5f_u32,
    0x9515929c_u32,
    0xebbf6d7a_u32,
    0xda955259_u32,
    0x2dd4be83_u32,
    0xd3587421_u32,
    0x2949e069_u32,
    0x448ec9c8_u32,
    0x6a75c289_u32,
    0x78f48e79_u32,
    0x6b99583e_u32,
    0xdd27b971_u32,
    0xb6bee14f_u32,
    0x17f088ad_u32,
    0x66c920ac_u32,
    0xb47dce3a_u32,
    0x1863df4a_u32,
    0x82e51a31_u32,
    0x60975133_u32,
    0x4562537f_u32,
    0xe0b16477_u32,
    0x84bb6bae_u32,
    0x1cfe81a0_u32,
    0x94f9082b_u32,
    0x58704868_u32,
    0x198f45fd_u32,
    0x8794de6c_u32,
    0xb7527bf8_u32,
    0x23ab73d3_u32,
    0xe2724b02_u32,
    0x57e31f8f_u32,
    0x2a6655ab_u32,
    0x07b2eb28_u32,
    0x032fb5c2_u32,
    0x9a86c57b_u32,
    0xa5d33708_u32,
    0xf2302887_u32,
    0xb223bfa5_u32,
    0xba02036a_u32,
    0x5ced1682_u32,
    0x2b8acf1c_u32,
    0x92a779b4_u32,
    0xf0f307f2_u32,
    0xa14e69e2_u32,
    0xcd65daf4_u32,
    0xd50605be_u32,
    0x1fd13462_u32,
    0x8ac4a6fe_u32,
    0x9d342e53_u32,
    0xa0a2f355_u32,
    0x32058ae1_u32,
    0x75a4f6eb_u32,
    0x390b83ec_u32,
    0xaa4060ef_u32,
    0x065e719f_u32,
    0x51bd6e10_u32,
    0xf93e218a_u32,
    0x3d96dd06_u32,
    0xaedd3e05_u32,
    0x464de6bd_u32,
    0xb591548d_u32,
    0x0571c45d_u32,
    0x6f0406d4_u32,
    0xff605015_u32,
    0x241998fb_u32,
    0x97d6bde9_u32,
    0xcc894043_u32,
    0x7767d99e_u32,
    0xbdb0e842_u32,
    0x8807898b_u32,
    0x38e7195b_u32,
    0xdb79c8ee_u32,
    0x47a17c0a_u32,
    0xe97c420f_u32,
    0xc9f8841e_u32,
    0x00000000_u32,
    0x83098086_u32,
    0x48322bed_u32,
    0xac1e1170_u32,
    0x4e6c5a72_u32,
    0xfbfd0eff_u32,
    0x560f8538_u32,
    0x1e3daed5_u32,
    0x27362d39_u32,
    0x640a0fd9_u32,
    0x21685ca6_u32,
    0xd19b5b54_u32,
    0x3a24362e_u32,
    0xb10c0a67_u32,
    0x0f9357e7_u32,
    0xd2b4ee96_u32,
    0x9e1b9b91_u32,
    0x4f80c0c5_u32,
    0xa261dc20_u32,
    0x695a774b_u32,
    0x161c121a_u32,
    0x0ae293ba_u32,
    0xe5c0a02a_u32,
    0x433c22e0_u32,
    0x1d121b17_u32,
    0x0b0e090d_u32,
    0xadf28bc7_u32,
    0xb92db6a8_u32,
    0xc8141ea9_u32,
    0x8557f119_u32,
    0x4caf7507_u32,
    0xbbee99dd_u32,
    0xfda37f60_u32,
    0x9ff70126_u32,
    0xbc5c72f5_u32,
    0xc544663b_u32,
    0x345bfb7e_u32,
    0x768b4329_u32,
    0xdccb23c6_u32,
    0x68b6edfc_u32,
    0x63b8e4f1_u32,
    0xcad731dc_u32,
    0x10426385_u32,
    0x40139722_u32,
    0x2084c611_u32,
    0x7d854a24_u32,
    0xf8d2bb3d_u32,
    0x11aef932_u32,
    0x6dc729a1_u32,
    0x4b1d9e2f_u32,
    0xf3dcb230_u32,
    0xec0d8652_u32,
    0xd077c1e3_u32,
    0x6c2bb316_u32,
    0x99a970b9_u32,
    0xfa119448_u32,
    0x2247e964_u32,
    0xc4a8fc8c_u32,
    0x1aa0f03f_u32,
    0xd8567d2c_u32,
    0xef223390_u32,
    0xc787494e_u32,
    0xc1d938d1_u32,
    0xfe8ccaa2_u32,
    0x3698d40b_u32,
    0xcfa6f581_u32,
    0x28a57ade_u32,
    0x26dab78e_u32,
    0xa43fadbf_u32,
    0xe42c3a9d_u32,
    0x0d507892_u32,
    0x9b6a5fcc_u32,
    0x62547e46_u32,
    0xc2f68d13_u32,
    0xe890d8b8_u32,
    0x5e2e39f7_u32,
    0xf582c3af_u32,
    0xbe9f5d80_u32,
    0x7c69d093_u32,
    0xa96fd52d_u32,
    0xb3cf2512_u32,
    0x3bc8ac99_u32,
    0xa710187d_u32,
    0x6ee89c63_u32,
    0x7bdb3bbb_u32,
    0x09cd2678_u32,
    0xf46e5918_u32,
    0x01ec9ab7_u32,
    0xa8834f9a_u32,
    0x65e6956e_u32,
    0x7eaaffe6_u32,
    0x0821bccf_u32,
    0xe6ef15e8_u32,
    0xd9bae79b_u32,
    0xce4a6f36_u32,
    0xd4ea9f09_u32,
    0xd629b07c_u32,
    0xaf31a4b2_u32,
    0x312a3f23_u32,
    0x30c6a594_u32,
    0xc035a266_u32,
    0x37744ebc_u32,
    0xa6fc82ca_u32,
    0xb0e090d0_u32,
    0x1533a7d8_u32,
    0x4af10498_u32,
    0xf741ecda_u32,
    0x0e7fcd50_u32,
    0x2f1791f6_u32,
    0x8d764dd6_u32,
    0x4d43efb0_u32,
    0x54ccaa4d_u32,
    0xdfe49604_u32,
    0xe39ed1b5_u32,
    0x1b4c6a88_u32,
    0xb8c12c1f_u32,
    0x7f466551_u32,
    0x049d5eea_u32,
    0x5d018c35_u32,
    0x73fa8774_u32,
    0x2efb0b41_u32,
    0x5ab3671d_u32,
    0x5292dbd2_u32,
    0x33e91056_u32,
    0x136dd647_u32,
    0x8c9ad761_u32,
    0x7a37a10c_u32,
    0x8e59f814_u32,
    0x89eb133c_u32,
    0xeecea927_u32,
    0x35b761c9_u32,
    0xede11ce5_u32,
    0x3c7a47b1_u32,
    0x599cd2df_u32,
    0x3f55f273_u32,
    0x791814ce_u32,
    0xbf73c737_u32,
    0xea53f7cd_u32,
    0x5b5ffdaa_u32,
    0x14df3d6f_u32,
    0x867844db_u32,
    0x81caaff3_u32,
    0x3eb968c4_u32,
    0x2c382434_u32,
    0x5fc2a340_u32,
    0x72161dc3_u32,
    0x0cbce225_u32,
    0x8b283c49_u32,
    0x41ff0d95_u32,
    0x7139a801_u32,
    0xde080cb3_u32,
    0x9cd8b4e4_u32,
    0x906456c1_u32,
    0x617bcb84_u32,
    0x70d532b6_u32,
    0x74486c5c_u32,
    0x42d0b857_u32,
];

static TD2: [u32; 256] = [
    0xa75051f4_u32,
    0x65537e41_u32,
    0xa4c31a17_u32,
    0x5e963a27_u32,
    0x6bcb3bab_u32,
    0x45f11f9d_u32,
    0x58abacfa_u32,
    0x03934be3_u32,
    0xfa552030_u32,
    0x6df6ad76_u32,
    0x769188cc_u32,
    0x4c25f502_u32,
    0xd7fc4fe5_u32,
    0xcbd7c52a_u32,
    0x44802635_u32,
    0xa38fb562_u32,
    0x5a49deb1_u32,
    0x1b6725ba_u32,
    0x0e9845ea_u32,
    0xc0e15dfe_u32,
    0x7502c32f_u32,
    0xf012814c_u32,
    0x97a38d46_u32,
    0xf9c66bd3_u32,
    0x5fe7038f_u32,
    0x9c951592_u32,
    0x7aebbf6d_u32,
    0x59da9552_u32,
    0x832dd4be_u32,
    0x21d35874_u32,
    0x692949e0_u32,
    0xc8448ec9_u32,
    0x896a75c2_u32,
    0x7978f48e_u32,
    0x3e6b9958_u32,
    0x71dd27b9_u32,
    0x4fb6bee1_u32,
    0xad17f088_u32,
    0xac66c920_u32,
    0x3ab47dce_u32,
    0x4a1863df_u32,
    0x3182e51a_u32,
    0x33609751_u32,
    0x7f456253_u32,
    0x77e0b164_u32,
    0xae84bb6b_u32,
    0xa01cfe81_u32,
    0x2b94f908_u32,
    0x68587048_u32,
    0xfd198f45_u32,
    0x6c8794de_u32,
    0xf8b7527b_u32,
    0xd323ab73_u32,
    0x02e2724b_u32,
    0x8f57e31f_u32,
    0xab2a6655_u32,
    0x2807b2eb_u32,
    0xc2032fb5_u32,
    0x7b9a86c5_u32,
    0x08a5d337_u32,
    0x87f23028_u32,
    0xa5b223bf_u32,
    0x6aba0203_u32,
    0x825ced16_u32,
    0x1c2b8acf_u32,
    0xb492a779_u32,
    0xf2f0f307_u32,
    0xe2a14e69_u32,
    0xf4cd65da_u32,
    0xbed50605_u32,
    0x621fd134_u32,
    0xfe8ac4a6_u32,
    0x539d342e_u32,
    0x55a0a2f3_u32,
    0xe132058a_u32,
    0xeb75a4f6_u32,
    0xec390b83_u32,
    0xefaa4060_u32,
    0x9f065e71_u32,
    0x1051bd6e_u32,
    0x8af93e21_u32,
    0x063d96dd_u32,
    0x05aedd3e_u32,
    0xbd464de6_u32,
    0x8db59154_u32,
    0x5d0571c4_u32,
    0xd46f0406_u32,
    0x15ff6050_u32,
    0xfb241998_u32,
    0xe997d6bd_u32,
    0x43cc8940_u32,
    0x9e7767d9_u32,
    0x42bdb0e8_u32,
    0x8b880789_u32,
    0x5b38e719_u32,
    0xeedb79c8_u32,
    0x0a47a17c_u32,
    0x0fe97c42_u32,
    0x1ec9f884_u32,
    0x00000000_u32,
    0x86830980_u32,
    0xed48322b_u32,
    0x70ac1e11_u32,
    0x724e6c5a_u32,
    0xfffbfd0e_u32,
    0x38560f85_u32,
    0xd51e3dae_u32,
    0x3927362d_u32,
    0xd9640a0f_u32,
    0xa621685c_u32,
    0x54d19b5b_u32,
    0x2e3a2436_u32,
    0x67b10c0a_u32,
    0xe70f9357_u32,
    0x96d2b4ee_u32,
    0x919e1b9b_u32,
    0xc54f80c0_u32,
    0x20a261dc_u32,
    0x4b695a77_u32,
    0x1a161c12_u32,
    0xba0ae293_u32,
    0x2ae5c0a0_u32,
    0xe0433c22_u32,
    0x171d121b_u32,
    0x0d0b0e09_u32,
    0xc7adf28b_u32,
    0xa8b92db6_u32,
    0xa9c8141e_u32,
    0x198557f1_u32,
    0x074caf75_u32,
    0xddbbee99_u32,
    0x60fda37f_u32,
    0x269ff701_u32,
    0xf5bc5c72_u32,
    0x3bc54466_u32,
    0x7e345bfb_u32,
    0x29768b43_u32,
    0xc6dccb23_u32,
    0xfc68b6ed_u32,
    0xf163b8e4_u32,
    0xdccad731_u32,
    0x85104263_u32,
    0x22401397_u32,
    0x112084c6_u32,
    0x247d854a_u32,
    0x3df8d2bb_u32,
    0x3211aef9_u32,
    0xa16dc729_u32,
    0x2f4b1d9e_u32,
    0x30f3dcb2_u32,
    0x52ec0d86_u32,
    0xe3d077c1_u32,
    0x166c2bb3_u32,
    0xb999a970_u32,
    0x48fa1194_u32,
    0x642247e9_u32,
    0x8cc4a8fc_u32,
    0x3f1aa0f0_u32,
    0x2cd8567d_u32,
    0x90ef2233_u32,
    0x4ec78749_u32,
    0xd1c1d938_u32,
    0xa2fe8cca_u32,
    0x0b3698d4_u32,
    0x81cfa6f5_u32,
    0xde28a57a_u32,
    0x8e26dab7_u32,
    0xbfa43fad_u32,
    0x9de42c3a_u32,
    0x920d5078_u32,
    0xcc9b6a5f_u32,
    0x4662547e_u32,
    0x13c2f68d_u32,
    0xb8e890d8_u32,
    0xf75e2e39_u32,
    0xaff582c3_u32,
    0x80be9f5d_u32,
    0x937c69d0_u32,
    0x2da96fd5_u32,
    0x12b3cf25_u32,
    0x993bc8ac_u32,
    0x7da71018_u32,
    0x636ee89c_u32,
    0xbb7bdb3b_u32,
    0x7809cd26_u32,
    0x18f46e59_u32,
    0xb701ec9a_u32,
    0x9aa8834f_u32,
    0x6e65e695_u32,
    0xe67eaaff_u32,
    0xcf0821bc_u32,
    0xe8e6ef15_u32,
    0x9bd9bae7_u32,
    0x36ce4a6f_u32,
    0x09d4ea9f_u32,
    0x7cd629b0_u32,
    0xb2af31a4_u32,
    0x23312a3f_u32,
    0x9430c6a5_u32,
    0x66c035a2_u32,
    0xbc37744e_u32,
    0xcaa6fc82_u32,
    0xd0b0e090_u32,
    0xd81533a7_u32,
    0x984af104_u32,
    0xdaf741ec_u32,
    0x500e7fcd_u32,
    0xf62f1791_u32,
    0xd68d764d_u32,
    0xb04d43ef_u32,
    0x4d54ccaa_u32,
    0x04dfe496_u32,
    0xb5e39ed1_u32,
    0x881b4c6a_u32,
    0x1fb8c12c_u32,
    0x517f4665_u32,
    0xea049d5e_u32,
    0x355d018c_u32,
    0x7473fa87_u32,
    0x412efb0b_u32,
    0x1d5ab367_u32,
    0xd25292db_u32,
    0x5633e910_u32,
    0x47136dd6_u32,
    0x618c9ad7_u32,
    0x0c7a37a1_u32,
    0x148e59f8_u32,
    0x3c89eb13_u32,
    0x27eecea9_u32,
    0xc935b761_u32,
    0xe5ede11c_u32,
    0xb13c7a47_u32,
    0xdf599cd2_u32,
    0x733f55f2_u32,
    0xce791814_u32,
    0x37bf73c7_u32,
    0xcdea53f7_u32,
    0xaa5b5ffd_u32,
    0x6f14df3d_u32,
    0xdb867844_u32,
    0xf381caaf_u32,
    0xc43eb968_u32,
    0x342c3824_u32,
    0x405fc2a3_u32,
    0xc372161d_u32,
    0x250cbce2_u32,
    0x498b283c_u32,
    0x9541ff0d_u32,
    0x017139a8_u32,
    0xb3de080c_u32,
    0xe49cd8b4_u32,
    0xc1906456_u32,
    0x84617bcb_u32,
    0xb670d532_u32,
    0x5c74486c_u32,
    0x5742d0b8_u32,
];

static TD3: [u32; 256] = [
    0xf4a75051_u32,
    0x4165537e_u32,
    0x17a4c31a_u32,
    0x275e963a_u32,
    0xab6bcb3b_u32,
    0x9d45f11f_u32,
    0xfa58abac_u32,
    0xe303934b_u32,
    0x30fa5520_u32,
    0x766df6ad_u32,
    0xcc769188_u32,
    0x024c25f5_u32,
    0xe5d7fc4f_u32,
    0x2acbd7c5_u32,
    0x35448026_u32,
    0x62a38fb5_u32,
    0xb15a49de_u32,
    0xba1b6725_u32,
    0xea0e9845_u32,
    0xfec0e15d_u32,
    0x2f7502c3_u32,
    0x4cf01281_u32,
    0x4697a38d_u32,
    0xd3f9c66b_u32,
    0x8f5fe703_u32,
    0x929c9515_u32,
    0x6d7aebbf_u32,
    0x5259da95_u32,
    0xbe832dd4_u32,
    0x7421d358_u32,
    0xe0692949_u32,
    0xc9c8448e_u32,
    0xc2896a75_u32,
    0x8e7978f4_u32,
    0x583e6b99_u32,
    0xb971dd27_u32,
    0xe14fb6be_u32,
    0x88ad17f0_u32,
    0x20ac66c9_u32,
    0xce3ab47d_u32,
    0xdf4a1863_u32,
    0x1a3182e5_u32,
    0x51336097_u32,
    0x537f4562_u32,
    0x6477e0b1_u32,
    0x6bae84bb_u32,
    0x81a01cfe_u32,
    0x082b94f9_u32,
    0x48685870_u32,
    0x45fd198f_u32,
    0xde6c8794_u32,
    0x7bf8b752_u32,
    0x73d323ab_u32,
    0x4b02e272_u32,
    0x1f8f57e3_u32,
    0x55ab2a66_u32,
    0xeb2807b2_u32,
    0xb5c2032f_u32,
    0xc57b9a86_u32,
    0x3708a5d3_u32,
    0x2887f230_u32,
    0xbfa5b223_u32,
    0x036aba02_u32,
    0x16825ced_u32,
    0xcf1c2b8a_u32,
    0x79b492a7_u32,
    0x07f2f0f3_u32,
    0x69e2a14e_u32,
    0xdaf4cd65_u32,
    0x05bed506_u32,
    0x34621fd1_u32,
    0xa6fe8ac4_u32,
    0x2e539d34_u32,
    0xf355a0a2_u32,
    0x8ae13205_u32,
    0xf6eb75a4_u32,
    0x83ec390b_u32,
    0x60efaa40_u32,
    0x719f065e_u32,
    0x6e1051bd_u32,
    0x218af93e_u32,
    0xdd063d96_u32,
    0x3e05aedd_u32,
    0xe6bd464d_u32,
    0x548db591_u32,
    0xc45d0571_u32,
    0x06d46f04_u32,
    0x5015ff60_u32,
    0x98fb2419_u32,
    0xbde997d6_u32,
    0x4043cc89_u32,
    0xd99e7767_u32,
    0xe842bdb0_u32,
    0x898b8807_u32,
    0x195b38e7_u32,
    0xc8eedb79_u32,
    0x7c0a47a1_u32,
    0x420fe97c_u32,
    0x841ec9f8_u32,
    0x00000000_u32,
    0x80868309_u32,
    0x2bed4832_u32,
    0x1170ac1e_u32,
    0x5a724e6c_u32,
    0x0efffbfd_u32,
    0x8538560f_u32,
    0xaed51e3d_u32,
    0x2d392736_u32,
    0x0fd9640a_u32,
    0x5ca62168_u32,
    0x5b54d19b_u32,
    0x362e3a24_u32,
    0x0a67b10c_u32,
    0x57e70f93_u32,
    0xee96d2b4_u32,
    0x9b919e1b_u32,
    0xc0c54f80_u32,
    0xdc20a261_u32,
    0x774b695a_u32,
    0x121a161c_u32,
    0x93ba0ae2_u32,
    0xa02ae5c0_u32,
    0x22e0433c_u32,
    0x1b171d12_u32,
    0x090d0b0e_u32,
    0x8bc7adf2_u32,
    0xb6a8b92d_u32,
    0x1ea9c814_u32,
    0xf1198557_u32,
    0x75074caf_u32,
    0x99ddbbee_u32,
    0x7f60fda3_u32,
    0x01269ff7_u32,
    0x72f5bc5c_u32,
    0x663bc544_u32,
    0xfb7e345b_u32,
    0x4329768b_u32,
    0x23c6dccb_u32,
    0xedfc68b6_u32,
    0xe4f163b8_u32,
    0x31dccad7_u32,
    0x63851042_u32,
    0x97224013_u32,
    0xc6112084_u32,
    0x4a247d85_u32,
    0xbb3df8d2_u32,
    0xf93211ae_u32,
    0x29a16dc7_u32,
    0x9e2f4b1d_u32,
    0xb230f3dc_u32,
    0x8652ec0d_u32,
    0xc1e3d077_u32,
    0xb3166c2b_u32,
    0x70b999a9_u32,
    0x9448fa11_u32,
    0xe9642247_u32,
    0xfc8cc4a8_u32,
    0xf03f1aa0_u32,
    0x7d2cd856_u32,
    0x3390ef22_u32,
    0x494ec787_u32,
    0x38d1c1d9_u32,
    0xcaa2fe8c_u32,
    0xd40b3698_u32,
    0xf581cfa6_u32,
    0x7ade28a5_u32,
    0xb78e26da_u32,
    0xadbfa43f_u32,
    0x3a9de42c_u32,
    0x78920d50_u32,
    0x5fcc9b6a_u32,
    0x7e466254_u32,
    0x8d13c2f6_u32,
    0xd8b8e890_u32,
    0x39f75e2e_u32,
    0xc3aff582_u32,
    0x5d80be9f_u32,
    0xd0937c69_u32,
    0xd52da96f_u32,
    0x2512b3cf_u32,
    0xac993bc8_u32,
    0x187da710_u32,
    0x9c636ee8_u32,
    0x3bbb7bdb_u32,
    0x267809cd_u32,
    0x5918f46e_u32,
    0x9ab701ec_u32,
    0x4f9aa883_u32,
    0x956e65e6_u32,
    0xffe67eaa_u32,
    0xbccf0821_u32,
    0x15e8e6ef_u32,
    0xe79bd9ba_u32,
    0x6f36ce4a_u32,
    0x9f09d4ea_u32,
    0xb07cd629_u32,
    0xa4b2af31_u32,
    0x3f23312a_u32,
    0xa59430c6_u32,
    0xa266c035_u32,
    0x4ebc3774_u32,
    0x82caa6fc_u32,
    0x90d0b0e0_u32,
    0xa7d81533_u32,
    0x04984af1_u32,
    0xecdaf741_u32,
    0xcd500e7f_u32,
    0x91f62f17_u32,
    0x4dd68d76_u32,
    0xefb04d43_u32,
    0xaa4d54cc_u32,
    0x9604dfe4_u32,
    0xd1b5e39e_u32,
    0x6a881b4c_u32,
    0x2c1fb8c1_u32,
    0x65517f46_u32,
    0x5eea049d_u32,
    0x8c355d01_u32,
    0x877473fa_u32,
    0x0b412efb_u32,
    0x671d5ab3_u32,
    0xdbd25292_u32,
    0x105633e9_u32,
    0xd647136d_u32,
    0xd7618c9a_u32,
    0xa10c7a37_u32,
    0xf8148e59_u32,
    0x133c89eb_u32,
    0xa927eece_u32,
    0x61c935b7_u32,
    0x1ce5ede1_u32,
    0x47b13c7a_u32,
    0xd2df599c_u32,
    0xf2733f55_u32,
    0x14ce7918_u32,
    0xc737bf73_u32,
    0xf7cdea53_u32,
    0xfdaa5b5f_u32,
    0x3d6f14df_u32,
    0x44db8678_u32,
    0xaff381ca_u32,
    0x68c43eb9_u32,
    0x24342c38_u32,
    0xa3405fc2_u32,
    0x1dc37216_u32,
    0xe2250cbc_u32,
    0x3c498b28_u32,
    0x0d9541ff_u32,
    0xa8017139_u32,
    0x0cb3de08_u32,
    0xb4e49cd8_u32,
    0x56c19064_u32,
    0xcb84617b_u32,
    0x32b670d5_u32,
    0x6c5c7448_u32,
    0xb85742d0_u32,
];

static TD4: [u32; 256] = [
    0x52525252_u32,
    0x09090909_u32,
    0x6a6a6a6a_u32,
    0xd5d5d5d5_u32,
    0x30303030_u32,
    0x36363636_u32,
    0xa5a5a5a5_u32,
    0x38383838_u32,
    0xbfbfbfbf_u32,
    0x40404040_u32,
    0xa3a3a3a3_u32,
    0x9e9e9e9e_u32,
    0x81818181_u32,
    0xf3f3f3f3_u32,
    0xd7d7d7d7_u32,
    0xfbfbfbfb_u32,
    0x7c7c7c7c_u32,
    0xe3e3e3e3_u32,
    0x39393939_u32,
    0x82828282_u32,
    0x9b9b9b9b_u32,
    0x2f2f2f2f_u32,
    0xffffffff_u32,
    0x87878787_u32,
    0x34343434_u32,
    0x8e8e8e8e_u32,
    0x43434343_u32,
    0x44444444_u32,
    0xc4c4c4c4_u32,
    0xdededede_u32,
    0xe9e9e9e9_u32,
    0xcbcbcbcb_u32,
    0x54545454_u32,
    0x7b7b7b7b_u32,
    0x94949494_u32,
    0x32323232_u32,
    0xa6a6a6a6_u32,
    0xc2c2c2c2_u32,
    0x23232323_u32,
    0x3d3d3d3d_u32,
    0xeeeeeeee_u32,
    0x4c4c4c4c_u32,
    0x95959595_u32,
    0x0b0b0b0b_u32,
    0x42424242_u32,
    0xfafafafa_u32,
    0xc3c3c3c3_u32,
    0x4e4e4e4e_u32,
    0x08080808_u32,
    0x2e2e2e2e_u32,
    0xa1a1a1a1_u32,
    0x66666666_u32,
    0x28282828_u32,
    0xd9d9d9d9_u32,
    0x24242424_u32,
    0xb2b2b2b2_u32,
    0x76767676_u32,
    0x5b5b5b5b_u32,
    0xa2a2a2a2_u32,
    0x49494949_u32,
    0x6d6d6d6d_u32,
    0x8b8b8b8b_u32,
    0xd1d1d1d1_u32,
    0x25252525_u32,
    0x72727272_u32,
    0xf8f8f8f8_u32,
    0xf6f6f6f6_u32,
    0x64646464_u32,
    0x86868686_u32,
    0x68686868_u32,
    0x98989898_u32,
    0x16161616_u32,
    0xd4d4d4d4_u32,
    0xa4a4a4a4_u32,
    0x5c5c5c5c_u32,
    0xcccccccc_u32,
    0x5d5d5d5d_u32,
    0x65656565_u32,
    0xb6b6b6b6_u32,
    0x92929292_u32,
    0x6c6c6c6c_u32,
    0x70707070_u32,
    0x48484848_u32,
    0x50505050_u32,
    0xfdfdfdfd_u32,
    0xedededed_u32,
    0xb9b9b9b9_u32,
    0xdadadada_u32,
    0x5e5e5e5e_u32,
    0x15151515_u32,
    0x46464646_u32,
    0x57575757_u32,
    0xa7a7a7a7_u32,
    0x8d8d8d8d_u32,
    0x9d9d9d9d_u32,
    0x84848484_u32,
    0x90909090_u32,
    0xd8d8d8d8_u32,
    0xabababab_u32,
    0x00000000_u32,
    0x8c8c8c8c_u32,
    0xbcbcbcbc_u32,
    0xd3d3d3d3_u32,
    0x0a0a0a0a_u32,
    0xf7f7f7f7_u32,
    0xe4e4e4e4_u32,
    0x58585858_u32,
    0x05050505_u32,
    0xb8b8b8b8_u32,
    0xb3b3b3b3_u32,
    0x45454545_u32,
    0x06060606_u32,
    0xd0d0d0d0_u32,
    0x2c2c2c2c_u32,
    0x1e1e1e1e_u32,
    0x8f8f8f8f_u32,
    0xcacacaca_u32,
    0x3f3f3f3f_u32,
    0x0f0f0f0f_u32,
    0x02020202_u32,
    0xc1c1c1c1_u32,
    0xafafafaf_u32,
    0xbdbdbdbd_u32,
    0x03030303_u32,
    0x01010101_u32,
    0x13131313_u32,
    0x8a8a8a8a_u32,
    0x6b6b6b6b_u32,
    0x3a3a3a3a_u32,
    0x91919191_u32,
    0x11111111_u32,
    0x41414141_u32,
    0x4f4f4f4f_u32,
    0x67676767_u32,
    0xdcdcdcdc_u32,
    0xeaeaeaea_u32,
    0x97979797_u32,
    0xf2f2f2f2_u32,
    0xcfcfcfcf_u32,
    0xcececece_u32,
    0xf0f0f0f0_u32,
    0xb4b4b4b4_u32,
    0xe6e6e6e6_u32,
    0x73737373_u32,
    0x96969696_u32,
    0xacacacac_u32,
    0x74747474_u32,
    0x22222222_u32,
    0xe7e7e7e7_u32,
    0xadadadad_u32,
    0x35353535_u32,
    0x85858585_u32,
    0xe2e2e2e2_u32,
    0xf9f9f9f9_u32,
    0x37373737_u32,
    0xe8e8e8e8_u32,
    0x1c1c1c1c_u32,
    0x75757575_u32,
    0xdfdfdfdf_u32,
    0x6e6e6e6e_u32,
    0x47474747_u32,
    0xf1f1f1f1_u32,
    0x1a1a1a1a_u32,
    0x71717171_u32,
    0x1d1d1d1d_u32,
    0x29292929_u32,
    0xc5c5c5c5_u32,
    0x89898989_u32,
    0x6f6f6f6f_u32,
    0xb7b7b7b7_u32,
    0x62626262_u32,
    0x0e0e0e0e_u32,
    0xaaaaaaaa_u32,
    0x18181818_u32,
    0xbebebebe_u32,
    0x1b1b1b1b_u32,
    0xfcfcfcfc_u32,
    0x56565656_u32,
    0x3e3e3e3e_u32,
    0x4b4b4b4b_u32,
    0xc6c6c6c6_u32,
    0xd2d2d2d2_u32,
    0x79797979_u32,
    0x20202020_u32,
    0x9a9a9a9a_u32,
    0xdbdbdbdb_u32,
    0xc0c0c0c0_u32,
    0xfefefefe_u32,
    0x78787878_u32,
    0xcdcdcdcd_u32,
    0x5a5a5a5a_u32,
    0xf4f4f4f4_u32,
    0x1f1f1f1f_u32,
    0xdddddddd_u32,
    0xa8a8a8a8_u32,
    0x33333333_u32,
    0x88888888_u32,
    0x07070707_u32,
    0xc7c7c7c7_u32,
    0x31313131_u32,
    0xb1b1b1b1_u32,
    0x12121212_u32,
    0x10101010_u32,
    0x59595959_u32,
    0x27272727_u32,
    0x80808080_u32,
    0xecececec_u32,
    0x5f5f5f5f_u32,
    0x60606060_u32,
    0x51515151_u32,
    0x7f7f7f7f_u32,
    0xa9a9a9a9_u32,
    0x19191919_u32,
    0xb5b5b5b5_u32,
    0x4a4a4a4a_u32,
    0x0d0d0d0d_u32,
    0x2d2d2d2d_u32,
    0xe5e5e5e5_u32,
    0x7a7a7a7a_u32,
    0x9f9f9f9f_u32,
    0x93939393_u32,
    0xc9c9c9c9_u32,
    0x9c9c9c9c_u32,
    0xefefefef_u32,
    0xa0a0a0a0_u32,
    0xe0e0e0e0_u32,
    0x3b3b3b3b_u32,
    0x4d4d4d4d_u32,
    0xaeaeaeae_u32,
    0x2a2a2a2a_u32,
    0xf5f5f5f5_u32,
    0xb0b0b0b0_u32,
    0xc8c8c8c8_u32,
    0xebebebeb_u32,
    0xbbbbbbbb_u32,
    0x3c3c3c3c_u32,
    0x83838383_u32,
    0x53535353_u32,
    0x99999999_u32,
    0x61616161_u32,
    0x17171717_u32,
    0x2b2b2b2b_u32,
    0x04040404_u32,
    0x7e7e7e7e_u32,
    0xbabababa_u32,
    0x77777777_u32,
    0xd6d6d6d6_u32,
    0x26262626_u32,
    0xe1e1e1e1_u32,
    0x69696969_u32,
    0x14141414_u32,
    0x63636363_u32,
    0x55555555_u32,
    0x21212121_u32,
    0x0c0c0c0c_u32,
    0x7d7d7d7d_u32,
];

static RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000,
];

#[inline(always)]
pub fn get_u32(pt: &[u8]) -> u32 {
    ((pt[0] as u32) << 24) ^ ((pt[1] as u32) << 16) ^ ((pt[2] as u32) << 8) ^ (pt[3] as u32)
}

#[inline(always)]
pub fn put_u32(ct: &mut [u8], st: u32) {
    ct[0] = (st >> 24) as u8;
    ct[1] = (st >> 16) as u8;
    ct[2] = (st >> 8) as u8;
    ct[3] = st as u8;
}

pub fn rijndaelKeySetupEnc(mut rk: &mut [u32], cipher_key: &[u8], key_bits: i32) -> i32 {
    let i = 0;
    let mut temp: u32;

    rk[0] = get_u32(&cipher_key[0..]);
    rk[1] = get_u32(&cipher_key[4..]);
    rk[2] = get_u32(&cipher_key[8..]);
    rk[3] = get_u32(&cipher_key[12..]);
    if key_bits == 128 {
        loop {
            temp = rk[3];
            rk[4] = rk[0]
                ^ (TE4[(temp >> 16) as usize & 0xff] & 0xff000000)
                ^ (TE4[(temp >> 8) as usize & 0xff] & 0x00ff0000)
                ^ (TE4[temp as usize & 0xff] & 0x0000ff00)
                ^ (TE4[(temp >> 24) as usize] & 0x000000ff)
                ^ RCON[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            let j = i + 1;
            if j == 10 {
                return 10;
            }
            rk = &mut rk[4..];
        }
    }
    rk[4] = get_u32(&cipher_key[16..]);
    rk[5] = get_u32(&cipher_key[20..]);
    if key_bits == 192 {
        loop {
            temp = rk[5];
            rk[6] = rk[0]
                ^ (TE4[(temp >> 16) as usize & 0xff] & 0xff000000)
                ^ (TE4[(temp >> 8) as usize & 0xff] & 0x00ff0000)
                ^ (TE4[temp as usize & 0xff] & 0x0000ff00)
                ^ (TE4[(temp >> 24) as usize] & 0x000000ff)
                ^ RCON[i];
            rk[7] = rk[1] ^ rk[6];
            rk[8] = rk[2] ^ rk[7];
            rk[9] = rk[3] ^ rk[8];
            rk[10] = rk[4] ^ rk[9];
            rk[11] = rk[5] ^ rk[10];
            let j = i + 1;
            if j == 8 {
                return 12;
            }
            rk = &mut rk[6..];
        }
    }
    rk[6] = get_u32(&cipher_key[24..]);
    rk[7] = get_u32(&cipher_key[28..]);
    if key_bits == 256 {
        loop {
            temp = rk[7];
            rk[8] = rk[0]
                ^ (TE4[(temp >> 16) as usize & 0xff] & 0xff000000)
                ^ (TE4[(temp >> 8) as usize & 0xff] & 0x00ff0000)
                ^ (TE4[temp as usize & 0xff] & 0x0000ff00)
                ^ (TE4[(temp >> 24) as usize] & 0x000000ff)
                ^ RCON[i];
            rk[9] = rk[1] ^ rk[8];
            rk[10] = rk[2] ^ rk[9];
            rk[11] = rk[3] ^ rk[10];

            let j = i + 1;
            if j == 7 {
                return 14;
            }

            temp = rk[11];
            rk[12] = rk[4]
                ^ (TE4[(temp >> 24) as usize] & 0xff000000)
                ^ (TE4[(temp >> 16) as usize & 0xff] & 0x00ff0000)
                ^ (TE4[(temp >> 8) as usize & 0xff] & 0x0000ff00)
                ^ (TE4[(temp) as usize & 0xff] & 0x000000ff);
            rk[13] = rk[5] ^ rk[12];
            rk[14] = rk[6] ^ rk[13];
            rk[15] = rk[7] ^ rk[14];
            rk = &mut rk[8..];
        }
    }
    return 0;
}

pub fn rijndaelKeySetupDec(rk: &mut [u32], cipher_key: &[u8], key_bits: i32) -> i32 {
    let nr: i32;
    let mut i: usize;
    let mut j: usize;
    let mut temp: u32;

    // Expand the cipher key
    nr = rijndaelKeySetupEnc(rk, cipher_key, key_bits);

    // Invert the order of the round keys
    i = 0;
    j = 4 * nr as usize;
    while i < j {
        temp = rk[i];
        rk[i] = rk[j];
        rk[j] = temp;

        temp = rk[i + 1];
        rk[i + 1] = rk[j + 1];
        rk[j + 1] = temp;

        temp = rk[i + 2];
        rk[i + 2] = rk[j + 2];
        rk[j + 2] = temp;

        temp = rk[i + 3];
        rk[i + 3] = rk[j + 3];
        rk[j + 3] = temp;

        i += 4;
        j -= 4;
    }

    // Apply the inverse MixColumn transform to all round keys but the first and the last
    for i in 1..nr {
        let offset = i as usize * 4;
        rk[offset] = TD0[TE4[(rk[offset] >> 24) as usize] as usize]
            ^ TD1[TE4[(rk[offset] >> 16) as usize & 0xff] as usize]
            ^ TD2[TE4[(rk[offset] >> 8) as usize & 0xff] as usize]
            ^ TD3[TE4[(rk[offset]) as usize & 0xff] as usize];
        rk[offset + 1] = TD0[TE4[(rk[offset + 1] >> 24) as usize] as usize]
            ^ TD1[TE4[(rk[offset + 1] >> 16) as usize & 0xff] as usize]
            ^ TD2[TE4[(rk[offset + 1] >> 8) as usize & 0xff] as usize]
            ^ TD3[TE4[(rk[offset + 1]) as usize & 0xff] as usize];
        rk[offset + 2] = TD0[TE4[(rk[offset + 2] >> 24) as usize] as usize]
            ^ TD1[TE4[(rk[offset + 2] >> 16) as usize & 0xff] as usize]
            ^ TD2[TE4[(rk[offset + 2] >> 8) as usize & 0xff] as usize]
            ^ TD3[TE4[(rk[offset + 2]) as usize & 0xff] as usize];
        rk[offset + 3] = TD0[TE4[(rk[offset + 3] >> 24) as usize] as usize]
            ^ TD1[TE4[(rk[offset + 3] >> 16) as usize & 0xff] as usize]
            ^ TD2[TE4[(rk[offset + 3] >> 8) as usize & 0xff] as usize]
            ^ TD3[TE4[(rk[offset + 3]) as usize & 0xff] as usize];
    }

    nr
}

pub fn rijndaelDecrypt(mut rk: &[u32], nr: i32, ct: &[u8; 16], pt: &mut [u8; 16]) {
    let mut s0: u32;
    let mut s1: u32;
    let mut s2: u32;
    let mut s3: u32;
    let mut t0: u32;
    let mut t1: u32;
    let mut t2: u32;
    let mut t3: u32;

    #[cfg(not(FULL_UNROLL))]
    let r: i32;

    s0 = get_u32(&ct[0..4]) ^ rk[0];
    s1 = get_u32(&ct[4..8]) ^ rk[1];
    s2 = get_u32(&ct[8..12]) ^ rk[2];
    s3 = get_u32(&ct[12..16]) ^ rk[3];

    #[cfg(FULL_UNROLL)]
    {
        /* round 1: */
        t0 =
            TD0[s0 >> 24] ^ TD1[(s3 >> 16) & 0xff] ^ TD2[(s2 >> 8) & 0xff] ^ TD3[s1 & 0xff] ^ rk[4];
        t1 =
            TD0[s1 >> 24] ^ TD1[(s0 >> 16) & 0xff] ^ TD2[(s3 >> 8) & 0xff] ^ TD3[s2 & 0xff] ^ rk[5];
        t2 =
            TD0[s2 >> 24] ^ TD1[(s1 >> 16) & 0xff] ^ TD2[(s0 >> 8) & 0xff] ^ TD3[s3 & 0xff] ^ rk[6];
        t3 =
            TD0[s3 >> 24] ^ TD1[(s2 >> 16) & 0xff] ^ TD2[(s1 >> 8) & 0xff] ^ TD3[s0 & 0xff] ^ rk[7];
        /* round 2: */
        s0 =
            TD0[t0 >> 24] ^ TD1[(t3 >> 16) & 0xff] ^ TD2[(t2 >> 8) & 0xff] ^ TD3[t1 & 0xff] ^ rk[8];
        s1 =
            TD0[t1 >> 24] ^ TD1[(t0 >> 16) & 0xff] ^ TD2[(t3 >> 8) & 0xff] ^ TD3[t2 & 0xff] ^ rk[9];
        s2 = TD0[t2 >> 24]
            ^ TD1[(t1 >> 16) & 0xff]
            ^ TD2[(t0 >> 8) & 0xff]
            ^ TD3[t3 & 0xff]
            ^ rk[10];
        s3 = TD0[t3 >> 24]
            ^ TD1[(t2 >> 16) & 0xff]
            ^ TD2[(t1 >> 8) & 0xff]
            ^ TD3[t0 & 0xff]
            ^ rk[11];
        /* round 3: */
        t0 = TD0[s0 >> 24]
            ^ TD1[(s3 >> 16) & 0xff]
            ^ TD2[(s2 >> 8) & 0xff]
            ^ TD3[s1 & 0xff]
            ^ rk[12];
        t1 = TD0[s1 >> 24]
            ^ TD1[(s0 >> 16) & 0xff]
            ^ TD2[(s3 >> 8) & 0xff]
            ^ TD3[s2 & 0xff]
            ^ rk[13];
        t2 = TD0[s2 >> 24]
            ^ TD1[(s1 >> 16) & 0xff]
            ^ TD2[(s0 >> 8) & 0xff]
            ^ TD3[s3 & 0xff]
            ^ rk[14];
        t3 = TD0[s3 >> 24]
            ^ TD1[(s2 >> 16) & 0xff]
            ^ TD2[(s1 >> 8) & 0xff]
            ^ TD3[s0 & 0xff]
            ^ rk[15];
        /* round 4: */
        s0 = TD0[t0 >> 24]
            ^ TD1[(t3 >> 16) & 0xff]
            ^ TD2[(t2 >> 8) & 0xff]
            ^ TD3[t1 & 0xff]
            ^ rk[16];
        s1 = TD0[t1 >> 24]
            ^ TD1[(t0 >> 16) & 0xff]
            ^ TD2[(t3 >> 8) & 0xff]
            ^ TD3[t2 & 0xff]
            ^ rk[17];
        s2 = TD0[t2 >> 24]
            ^ TD1[(t1 >> 16) & 0xff]
            ^ TD2[(t0 >> 8) & 0xff]
            ^ TD3[t3 & 0xff]
            ^ rk[18];
        s3 = TD0[t3 >> 24]
            ^ TD1[(t2 >> 16) & 0xff]
            ^ TD2[(t1 >> 8) & 0xff]
            ^ TD3[t0 & 0xff]
            ^ rk[19];
        /* round 5: */
        t0 = TD0[s0 >> 24]
            ^ TD1[(s3 >> 16) & 0xff]
            ^ TD2[(s2 >> 8) & 0xff]
            ^ TD3[s1 & 0xff]
            ^ rk[20];
        t1 = TD0[s1 >> 24]
            ^ TD1[(s0 >> 16) & 0xff]
            ^ TD2[(s3 >> 8) & 0xff]
            ^ TD3[s2 & 0xff]
            ^ rk[21];
        t2 = TD0[s2 >> 24]
            ^ TD1[(s1 >> 16) & 0xff]
            ^ TD2[(s0 >> 8) & 0xff]
            ^ TD3[s3 & 0xff]
            ^ rk[22];
        t3 = TD0[s3 >> 24]
            ^ TD1[(s2 >> 16) & 0xff]
            ^ TD2[(s1 >> 8) & 0xff]
            ^ TD3[s0 & 0xff]
            ^ rk[23];
        /* round 6: */
        s0 = TD0[t0 >> 24]
            ^ TD1[(t3 >> 16) & 0xff]
            ^ TD2[(t2 >> 8) & 0xff]
            ^ TD3[t1 & 0xff]
            ^ rk[24];
        s1 = TD0[t1 >> 24]
            ^ TD1[(t0 >> 16) & 0xff]
            ^ TD2[(t3 >> 8) & 0xff]
            ^ TD3[t2 & 0xff]
            ^ rk[25];
        s2 = TD0[t2 >> 24]
            ^ TD1[(t1 >> 16) & 0xff]
            ^ TD2[(t0 >> 8) & 0xff]
            ^ TD3[t3 & 0xff]
            ^ rk[26];
        s3 = TD0[t3 >> 24]
            ^ TD1[(t2 >> 16) & 0xff]
            ^ TD2[(t1 >> 8) & 0xff]
            ^ TD3[t0 & 0xff]
            ^ rk[27];
        /* round 7: */
        t0 = TD0[s0 >> 24]
            ^ TD1[(s3 >> 16) & 0xff]
            ^ TD2[(s2 >> 8) & 0xff]
            ^ TD3[s1 & 0xff]
            ^ rk[28];
        t1 = TD0[s1 >> 24]
            ^ TD1[(s0 >> 16) & 0xff]
            ^ TD2[(s3 >> 8) & 0xff]
            ^ TD3[s2 & 0xff]
            ^ rk[29];
        t2 = TD0[s2 >> 24]
            ^ TD1[(s1 >> 16) & 0xff]
            ^ TD2[(s0 >> 8) & 0xff]
            ^ TD3[s3 & 0xff]
            ^ rk[30];
        t3 = TD0[s3 >> 24]
            ^ TD1[(s2 >> 16) & 0xff]
            ^ TD2[(s1 >> 8) & 0xff]
            ^ TD3[s0 & 0xff]
            ^ rk[31];
        /* round 8: */
        s0 = TD0[t0 >> 24]
            ^ TD1[(t3 >> 16) & 0xff]
            ^ TD2[(t2 >> 8) & 0xff]
            ^ TD3[t1 & 0xff]
            ^ rk[32];
        s1 = TD0[t1 >> 24]
            ^ TD1[(t0 >> 16) & 0xff]
            ^ TD2[(t3 >> 8) & 0xff]
            ^ TD3[t2 & 0xff]
            ^ rk[33];
        s2 = TD0[t2 >> 24]
            ^ TD1[(t1 >> 16) & 0xff]
            ^ TD2[(t0 >> 8) & 0xff]
            ^ TD3[t3 & 0xff]
            ^ rk[34];
        s3 = TD0[t3 >> 24]
            ^ TD1[(t2 >> 16) & 0xff]
            ^ TD2[(t1 >> 8) & 0xff]
            ^ TD3[t0 & 0xff]
            ^ rk[35];
        /* round 9: */
        t0 = TD0[s0 >> 24]
            ^ TD1[(s3 >> 16) & 0xff]
            ^ TD2[(s2 >> 8) & 0xff]
            ^ TD3[s1 & 0xff]
            ^ rk[36];
        t1 = TD0[s1 >> 24]
            ^ TD1[(s0 >> 16) & 0xff]
            ^ TD2[(s3 >> 8) & 0xff]
            ^ TD3[s2 & 0xff]
            ^ rk[37];
        t2 = TD0[s2 >> 24]
            ^ TD1[(s1 >> 16) & 0xff]
            ^ TD2[(s0 >> 8) & 0xff]
            ^ TD3[s3 & 0xff]
            ^ rk[38];
        t3 = TD0[s3 >> 24]
            ^ TD1[(s2 >> 16) & 0xff]
            ^ TD2[(s1 >> 8) & 0xff]
            ^ TD3[s0 & 0xff]
            ^ rk[39];
        if (nr > 10) {
            /* round 10: */
            s0 = TD0[t0 >> 24]
                ^ TD1[(t3 >> 16) & 0xff]
                ^ TD2[(t2 >> 8) & 0xff]
                ^ TD3[t1 & 0xff]
                ^ rk[40];
            s1 = TD0[t1 >> 24]
                ^ TD1[(t0 >> 16) & 0xff]
                ^ TD2[(t3 >> 8) & 0xff]
                ^ TD3[t2 & 0xff]
                ^ rk[41];
            s2 = TD0[t2 >> 24]
                ^ TD1[(t1 >> 16) & 0xff]
                ^ TD2[(t0 >> 8) & 0xff]
                ^ TD3[t3 & 0xff]
                ^ rk[42];
            s3 = TD0[t3 >> 24]
                ^ TD1[(t2 >> 16) & 0xff]
                ^ TD2[(t1 >> 8) & 0xff]
                ^ TD3[t0 & 0xff]
                ^ rk[43];
            /* round 11: */
            t0 = TD0[s0 >> 24]
                ^ TD1[(s3 >> 16) & 0xff]
                ^ TD2[(s2 >> 8) & 0xff]
                ^ TD3[s1 & 0xff]
                ^ rk[44];
            t1 = TD0[s1 >> 24]
                ^ TD1[(s0 >> 16) & 0xff]
                ^ TD2[(s3 >> 8) & 0xff]
                ^ TD3[s2 & 0xff]
                ^ rk[45];
            t2 = TD0[s2 >> 24]
                ^ TD1[(s1 >> 16) & 0xff]
                ^ TD2[(s0 >> 8) & 0xff]
                ^ TD3[s3 & 0xff]
                ^ rk[46];
            t3 = TD0[s3 >> 24]
                ^ TD1[(s2 >> 16) & 0xff]
                ^ TD2[(s1 >> 8) & 0xff]
                ^ TD3[s0 & 0xff]
                ^ rk[47];
            if (nr > 12) {
                /* round 12: */
                s0 = TD0[t0 >> 24]
                    ^ TD1[(t3 >> 16) & 0xff]
                    ^ TD2[(t2 >> 8) & 0xff]
                    ^ TD3[t1 & 0xff]
                    ^ rk[48];
                s1 = TD0[t1 >> 24]
                    ^ TD1[(t0 >> 16) & 0xff]
                    ^ TD2[(t3 >> 8) & 0xff]
                    ^ TD3[t2 & 0xff]
                    ^ rk[49];
                s2 = TD0[t2 >> 24]
                    ^ TD1[(t1 >> 16) & 0xff]
                    ^ TD2[(t0 >> 8) & 0xff]
                    ^ TD3[t3 & 0xff]
                    ^ rk[50];
                s3 = TD0[t3 >> 24]
                    ^ TD1[(t2 >> 16) & 0xff]
                    ^ TD2[(t1 >> 8) & 0xff]
                    ^ TD3[t0 & 0xff]
                    ^ rk[51];
                /* round 13: */
                t0 = TD0[s0 >> 24]
                    ^ TD1[(s3 >> 16) & 0xff]
                    ^ TD2[(s2 >> 8) & 0xff]
                    ^ TD3[s1 & 0xff]
                    ^ rk[52];
                t1 = TD0[s1 >> 24]
                    ^ TD1[(s0 >> 16) & 0xff]
                    ^ TD2[(s3 >> 8) & 0xff]
                    ^ TD3[s2 & 0xff]
                    ^ rk[53];
                t2 = TD0[s2 >> 24]
                    ^ TD1[(s1 >> 16) & 0xff]
                    ^ TD2[(s0 >> 8) & 0xff]
                    ^ TD3[s3 & 0xff]
                    ^ rk[54];
                t3 = TD0[s3 >> 24]
                    ^ TD1[(s2 >> 16) & 0xff]
                    ^ TD2[(s1 >> 8) & 0xff]
                    ^ TD3[s0 & 0xff]
                    ^ rk[55];
            }
        }
        rk += nr << 2;
    }

    #[cfg(not(FULL_UNROLL))]
    {
        /* nr - 1 full rounds: */
        r = nr >> 1;
        loop {
            t0 = TD0[(s0 >> 24) as usize]
                ^ TD1[(s3 >> 16) as usize & 0xff]
                ^ TD2[(s2 >> 8) as usize & 0xff]
                ^ TD3[(s1) as usize & 0xff]
                ^ rk[4];

            t1 = TD0[(s1 >> 24) as usize]
                ^ TD1[(s0 >> 16) as usize & 0xff]
                ^ TD2[(s3 >> 8) as usize & 0xff]
                ^ TD3[(s2) as usize & 0xff]
                ^ rk[5];

            t2 = TD0[(s2 >> 24) as usize]
                ^ TD1[(s1 >> 16) as usize & 0xff]
                ^ TD2[(s0 >> 8) as usize & 0xff]
                ^ TD3[(s3) as usize & 0xff]
                ^ rk[6];

            t3 = TD0[(s3 >> 24) as usize]
                ^ TD1[(s2 >> 16) as usize & 0xff]
                ^ TD2[(s1 >> 8) as usize & 0xff]
                ^ TD3[(s0) as usize & 0xff]
                ^ rk[7];

            // this c code somewhat illegal in rust is this equivalent add number to slice of u32 array
            // rk += 8; == &rk[8..] ??
            // correct me on this one
            rk = &rk[8..];

            if --r == 0 {
                break;
            }

            s0 = TD0[(t0 >> 24) as usize]
                ^ TD1[(t3 >> 16) as usize & 0xff]
                ^ TD2[(t2 >> 8) as usize & 0xff]
                ^ TD3[(t1) as usize & 0xff]
                ^ rk[0];

            s1 = TD0[(t1 >> 24) as usize]
                ^ TD1[(t0 >> 16) as usize & 0xff]
                ^ TD2[(t3 >> 8) as usize & 0xff]
                ^ TD3[(t2) as usize & 0xff]
                ^ rk[1];

            s2 = TD0[(t2 >> 24) as usize]
                ^ TD1[(t1 >> 16) as usize & 0xff]
                ^ TD2[(t0 >> 8) as usize & 0xff]
                ^ TD3[(t3) as usize & 0xff]
                ^ rk[2];

            s3 = TD0[(t3 >> 24) as usize]
                ^ TD1[(t2 >> 16) as usize & 0xff]
                ^ TD2[(t1 >> 8) as usize & 0xff]
                ^ TD3[(t0) as usize & 0xff]
                ^ rk[3];
        }
    }

    s0 = (TD4[(t0 >> 24) as usize] & 0xff000000)
        ^ (TD4[(t3 >> 16) as usize & 0xff] & 0x00ff0000)
        ^ (TD4[(t2 >> 8) as usize & 0xff] & 0x0000ff00)
        ^ (TD4[(t1) as usize & 0xff] & 0x000000ff)
        ^ rk[0];
    put_u32(pt, s0);

    s1 = (TD4[(t1 >> 24) as usize] & 0xff000000)
        ^ (TD4[(t0 >> 16) as usize & 0xff] & 0x00ff0000)
        ^ (TD4[(t3 >> 8) as usize & 0xff] & 0x0000ff00)
        ^ (TD4[(t2) as usize & 0xff] & 0x000000ff)
        ^ rk[1];
    put_u32(&mut pt[4..], s1);

    s2 = (TD4[(t2 >> 24) as usize] & 0xff000000)
        ^ (TD4[(t1 >> 16) as usize & 0xff] & 0x00ff0000)
        ^ (TD4[(t0 >> 8) as usize & 0xff] & 0x0000ff00)
        ^ (TD4[(t3) as usize & 0xff] & 0x000000ff)
        ^ rk[2];

    put_u32(&mut pt[8..], s2);
    s3 = (TD4[(t3 >> 24) as usize] & 0xff000000)
        ^ (TD4[(t2 >> 16) as usize & 0xff] & 0x00ff0000)
        ^ (TD4[(t1 >> 8) as usize & 0xff] & 0x0000ff00)
        ^ (TD4[(t0) as usize & 0xff] & 0x000000ff)
        ^ rk[3];
    put_u32(&mut pt[12..], s3);
}

pub fn rijndaelEncrypt(mut rk: &[u32], nr: i32, pt: &[u8; 16], ct: &mut [u8; 16]) {
    let mut s0: u32;
    let mut s1: u32;
    let mut s2: u32;
    let mut s3: u32;
    let mut t0: u32;
    let mut t1: u32;
    let mut t2: u32;
    let mut t3: u32;

    #[cfg(not(FULL_UNROLL))]
    let mut r: i32;

    s0 = get_u32(&pt[0..4]) ^ rk[0];
    s1 = get_u32(&pt[4..8]) ^ rk[1];
    s2 = get_u32(&pt[8..12]) ^ rk[2];
    s3 = get_u32(&pt[12..16]) ^ rk[3];

    #[cfg(FULL_UNROLL)]
    {
        // round:1
        t0 = TE0[(s0 >> 24) as usize]
            ^ TE1[((s1 >> 16) & 0xff) as usize]
            ^ TE2[((s2 >> 8) & 0xff) as usize]
            ^ TE3[(s3 & 0xff) as usize]
            ^ rk[4];
        t1 = TE0[(s1 >> 24) as usize]
            ^ TE1[((s2 >> 16) & 0xff) as usize]
            ^ TE2[((s3 >> 8) & 0xff) as usize]
            ^ TE3[(s0 & 0xff) as usize]
            ^ rk[5];
        t2 = TE0[(s2 >> 24) as usize]
            ^ TE1[((s3 >> 16) & 0xff) as usize]
            ^ TE2[((s0 >> 8) & 0xff) as usize]
            ^ TE3[(s1 & 0xff) as usize]
            ^ rk[6];
        t3 = TE0[(s3 >> 24) as usize]
            ^ TE1[((s0 >> 16) & 0xff) as usize]
            ^ TE2[((s1 >> 8) & 0xff) as usize]
            ^ TE3[(s2 & 0xff) as usize]
            ^ rk[7];

        // round 2:
        s0 = TE0[(t0 >> 24) as usize]
            ^ TE1[((t1 >> 16) & 0xff) as usize]
            ^ TE2[((t2 >> 8) & 0xff) as usize]
            ^ TE3[(t3 & 0xff) as usize]
            ^ rk[8];
        s1 = TE0[(t1 >> 24) as usize]
            ^ TE1[((t2 >> 16) & 0xff) as usize]
            ^ TE2[((t3 >> 8) & 0xff) as usize]
            ^ TE3[(t0 & 0xff) as usize]
            ^ rk[9];
        s2 = TE0[(t2 >> 24) as usize]
            ^ TE1[((t3 >> 16) & 0xff) as usize]
            ^ TE2[((t0 >> 8) & 0xff) as usize]
            ^ TE3[(t1 & 0xff) as usize]
            ^ rk[10];
        s3 = TE0[(t3 >> 24) as usize]
            ^ TE1[((t0 >> 16) & 0xff) as usize]
            ^ TE2[((t1 >> 8) & 0xff) as usize]
            ^ TE3[(t2 & 0xff) as usize]
            ^ rk[11];

        // round 3:
        t0 = TE0[(s0 >> 24) as usize]
            ^ TE1[((s1 >> 16) & 0xff) as usize]
            ^ TE2[((s2 >> 8) & 0xff) as usize]
            ^ TE3[(s3 & 0xff) as usize]
            ^ rk[12];
        t1 = TE0[(s1 >> 24) as usize]
            ^ TE1[((s2 >> 16) & 0xff) as usize]
            ^ TE2[((s3 >> 8) & 0xff) as usize]
            ^ TE3[(s0 & 0xff) as usize]
            ^ rk[13];
        t2 = TE0[(s2 >> 24) as usize]
            ^ TE1[((s3 >> 16) & 0xff) as usize]
            ^ TE2[((s0 >> 8) & 0xff) as usize]
            ^ TE3[(s1 & 0xff) as usize]
            ^ rk[14];
        t3 = TE0[(s3 >> 24) as usize]
            ^ TE1[((s0 >> 16) & 0xff) as usize]
            ^ TE2[((s1 >> 8) & 0xff) as usize]
            ^ TE3[(s2 & 0xff) as usize]
            ^ rk[15];

        // round 4
        s0 = TE0[(t0 >> 24) as usize]
            ^ TE1[((t1 >> 16) & 0xff) as usize]
            ^ TE2[((t2 >> 8) & 0xff) as usize]
            ^ TE3[(t3 & 0xff) as usize]
            ^ rk[16];
        s1 = TE0[(t1 >> 24) as usize]
            ^ TE1[((t2 >> 16) & 0xff) as usize]
            ^ TE2[((t3 >> 8) & 0xff) as usize]
            ^ TE3[(t0 & 0xff) as usize]
            ^ rk[17];
        s2 = TE0[(t2 >> 24) as usize]
            ^ TE1[((t3 >> 16) & 0xff) as usize]
            ^ TE2[((t0 >> 8) & 0xff) as usize]
            ^ TE3[(t1 & 0xff) as usize]
            ^ rk[18];
        s3 = TE0[(t3 >> 24) as usize]
            ^ TE1[((t0 >> 16) & 0xff) as usize]
            ^ TE2[((t1 >> 8) & 0xff) as usize]
            ^ TE3[(t2 & 0xff) as usize]
            ^ rk[19];

        // round 5
        t0 = TE0[(s0 >> 24) as usize]
            ^ TE1[((s1 >> 16) & 0xff) as usize]
            ^ TE2[((s2 >> 8) & 0xff) as usize]
            ^ TE3[(s3 & 0xff) as usize]
            ^ rk[20];
        t1 = TE0[(s1 >> 24) as usize]
            ^ TE1[((s2 >> 16) & 0xff) as usize]
            ^ TE2[((s3 >> 8) & 0xff) as usize]
            ^ TE3[(s0 & 0xff) as usize]
            ^ rk[21];
        t2 = TE0[(s2 >> 24) as usize]
            ^ TE1[((s3 >> 16) & 0xff) as usize]
            ^ TE2[((s0 >> 8) & 0xff) as usize]
            ^ TE3[(s1 & 0xff) as usize]
            ^ rk[22];
        t3 = TE0[(s3 >> 24) as usize]
            ^ TE1[((s0 >> 16) & 0xff) as usize]
            ^ TE2[((s1 >> 8) & 0xff) as usize]
            ^ TE3[(s2 & 0xff) as usize]
            ^ rk[23];

        // round 6
        s0 = TE0[(t0 >> 24) as usize]
            ^ TE1[((t1 >> 16) & 0xff) as usize]
            ^ TE2[((t2 >> 8) & 0xff) as usize]
            ^ TE3[(t3 & 0xff) as usize]
            ^ rk[24];
        s1 = TE0[(t1 >> 24) as usize]
            ^ TE1[((t2 >> 16) & 0xff) as usize]
            ^ TE2[((t3 >> 8) & 0xff) as usize]
            ^ TE3[(t0 & 0xff) as usize]
            ^ rk[25];
        s2 = TE0[(t2 >> 24) as usize]
            ^ TE1[((t3 >> 16) & 0xff) as usize]
            ^ TE2[((t0 >> 8) & 0xff) as usize]
            ^ TE3[(t1 & 0xff) as usize]
            ^ rk[26];
        s3 = TE0[(t3 >> 24) as usize]
            ^ TE1[((t0 >> 16) & 0xff) as usize]
            ^ TE2[((t1 >> 8) & 0xff) as usize]
            ^ TE3[(t2 & 0xff) as usize]
            ^ rk[27];

        // round 7
        t0 = TE0[(s0 >> 24) as usize]
            ^ TE1[((s1 >> 16) & 0xff) as usize]
            ^ TE2[((s2 >> 8) & 0xff) as usize]
            ^ TE3[(s3 & 0xff) as usize]
            ^ rk[28];
        t1 = TE0[(s1 >> 24) as usize]
            ^ TE1[((s2 >> 16) & 0xff) as usize]
            ^ TE2[((s3 >> 8) & 0xff) as usize]
            ^ TE3[(s0 & 0xff) as usize]
            ^ rk[29];
        t2 = TE0[(s2 >> 24) as usize]
            ^ TE1[((s3 >> 16) & 0xff) as usize]
            ^ TE2[((s0 >> 8) & 0xff) as usize]
            ^ TE3[(s1 & 0xff) as usize]
            ^ rk[30];
        t3 = TE0[(s3 >> 24) as usize]
            ^ TE1[((s0 >> 16) & 0xff) as usize]
            ^ TE2[((s1 >> 8) & 0xff) as usize]
            ^ TE3[(s2 & 0xff) as usize]
            ^ rk[31];

        // round:8
        s0 = TE0[(t0 >> 24) as usize]
            ^ TE1[((t1 >> 16) & 0xff) as usize]
            ^ TE2[((t2 >> 8) & 0xff) as usize]
            ^ TE3[(t3 & 0xff) as usize]
            ^ rk[32];
        s1 = TE0[(t1 >> 24) as usize]
            ^ TE1[((t2 >> 16) & 0xff) as usize]
            ^ TE2[((t3 >> 8) & 0xff) as usize]
            ^ TE3[(t0 & 0xff) as usize]
            ^ rk[33];
        s2 = TE0[(t2 >> 24) as usize]
            ^ TE1[((t3 >> 16) & 0xff) as usize]
            ^ TE2[((t0 >> 8) & 0xff) as usize]
            ^ TE3[(t1 & 0xff) as usize]
            ^ rk[34];
        s3 = TE0[(t3 >> 24) as usize]
            ^ TE1[((t0 >> 16) & 0xff) as usize]
            ^ TE2[((t1 >> 8) & 0xff) as usize]
            ^ TE3[(t2 & 0xff) as usize]
            ^ rk[35];

        /* round 9: */
        t0 = TE0[(s0 >> 24) as usize]
            ^ TE1[((s1 >> 16) & 0xff) as usize]
            ^ TE2[((s2 >> 8) & 0xff) as usize]
            ^ TE3[(s3 & 0xff) as usize]
            ^ rk[36];
        t1 = TE0[(s1 >> 24) as usize]
            ^ TE1[((s2 >> 16) & 0xff) as usize]
            ^ TE2[((s3 >> 8) & 0xff) as usize]
            ^ TE3[(s0 & 0xff) as usize]
            ^ rk[37];
        t2 = TE0[(s2 >> 24) as usize]
            ^ TE1[((s3 >> 16) & 0xff) as usize]
            ^ TE2[((s0 >> 8) & 0xff) as usize]
            ^ TE3[(s1 & 0xff) as usize]
            ^ rk[38];
        t3 = TE0[(s3 >> 24) as usize]
            ^ TE1[((s0 >> 16) & 0xff) as usize]
            ^ TE2[((s1 >> 8) & 0xff) as usize]
            ^ TE3[(s2 & 0xff) as usize]
            ^ rk[39];

        if nr > 10 {
            // round 10:
            s0 = TE0[(t0 >> 24) as usize]
                ^ TE1[((t1 >> 16) & 0xff) as usize]
                ^ TE2[((t2 >> 8) & 0xff) as usize]
                ^ TE3[(t3 & 0xff) as usize]
                ^ rk[40];
            s1 = TE0[(t1 >> 24) as usize]
                ^ TE1[((t2 >> 16) & 0xff) as usize]
                ^ TE2[((t3 >> 8) & 0xff) as usize]
                ^ TE3[(t0 & 0xff) as usize]
                ^ rk[41];
            s2 = TE0[(t2 >> 24) as usize]
                ^ TE1[((t3 >> 16) & 0xff) as usize]
                ^ TE2[((t0 >> 8) & 0xff) as usize]
                ^ TE3[(t1 & 0xff) as usize]
                ^ rk[42];
            s3 = TE0[(t3 >> 24) as usize]
                ^ TE1[((t0 >> 16) & 0xff) as usize]
                ^ TE2[((t1 >> 8) & 0xff) as usize]
                ^ TE3[(t2 & 0xff) as usize]
                ^ rk[43];
            // round 11:
            t0 = TE0[(s0 >> 24) as usize]
                ^ TE1[((s1 >> 16) & 0xff) as usize]
                ^ TE2[((s2 >> 8) & 0xff) as usize]
                ^ TE3[(s3 & 0xff) as usize]
                ^ rk[44];
            t1 = TE0[(s1 >> 24) as usize]
                ^ TE1[((s2 >> 16) & 0xff) as usize]
                ^ TE2[((s3 >> 8) & 0xff) as usize]
                ^ TE3[(s0 & 0xff) as usize]
                ^ rk[45];
            t2 = TE0[(s2 >> 24) as usize]
                ^ TE1[((s3 >> 16) & 0xff) as usize]
                ^ TE2[((s0 >> 8) & 0xff) as usize]
                ^ TE3[(s1 & 0xff) as usize]
                ^ rk[46];
            t3 = TE0[(s3 >> 24) as usize]
                ^ TE1[((s0 >> 16) & 0xff) as usize]
                ^ TE2[((s1 >> 8) & 0xff) as usize]
                ^ TE3[(s2 & 0xff) as usize]
                ^ rk[47];
            if nr > 12 {
                // round 12:
                s0 = TE0[(t0 >> 24) as usize]
                    ^ TE1[((t1 >> 16) & 0xff) as usize]
                    ^ TE2[((t2 >> 8) & 0xff) as usize]
                    ^ TE3[(t3 & 0xff) as usize]
                    ^ rk[48];
                s1 = TE0[(t1 >> 24) as usize]
                    ^ TE1[((t2 >> 16) & 0xff) as usize]
                    ^ TE2[((t3 >> 8) & 0xff) as usize]
                    ^ TE3[(t0 & 0xff) as usize]
                    ^ rk[49];
                s2 = TE0[(t2 >> 24) as usize]
                    ^ TE1[((t3 >> 16) & 0xff) as usize]
                    ^ TE2[((t0 >> 8) & 0xff) as usize]
                    ^ TE3[(t1 & 0xff) as usize]
                    ^ rk[50];
                s3 = TE0[(t3 >> 24) as usize]
                    ^ TE1[((t0 >> 16) & 0xff) as usize]
                    ^ TE2[((t1 >> 8) & 0xff) as usize]
                    ^ TE3[(t2 & 0xff) as usize]
                    ^ rk[51];

                // round 13:
                t0 = TE0[(s0 >> 24) as usize]
                    ^ TE1[((s1 >> 16) & 0xff) as usize]
                    ^ TE2[((s2 >> 8) & 0xff) as usize]
                    ^ TE3[(s3 & 0xff) as usize]
                    ^ rk[52];
                t1 = TE0[(s1 >> 24) as usize]
                    ^ TE1[((s2 >> 16) & 0xff) as usize]
                    ^ TE2[((s3 >> 8) & 0xff) as usize]
                    ^ TE3[(s0 & 0xff) as usize]
                    ^ rk[53];
                t2 = TE0[(s2 >> 24) as usize]
                    ^ TE1[((s3 >> 16) & 0xff) as usize]
                    ^ TE2[((s0 >> 8) & 0xff) as usize]
                    ^ TE3[(s1 & 0xff) as usize]
                    ^ rk[54];
                t3 = TE0[(s3 >> 24) as usize]
                    ^ TE1[((s0 >> 16) & 0xff) as usize]
                    ^ TE2[((s1 >> 8) & 0xff) as usize]
                    ^ TE3[(s2 & 0xff) as usize]
                    ^ rk[55];
            }
        }
        rk += nr << 2;

        //end of FULL_UNROLL
    }

    #[cfg(not(FULL_UNROLL))]
    {
        r = nr >> 1;
        loop {
            t0 = TE0[(s0 >> 24) as usize]
                ^ TE1[((s1 >> 16) & 0xff) as usize]
                ^ TE2[((s2 >> 8) & 0xff) as usize]
                ^ TE3[(s3 & 0xff) as usize]
                ^ rk[4];
            t1 = TE0[(s1 >> 24) as usize]
                ^ TE1[((s2 >> 16) & 0xff) as usize]
                ^ TE2[((s3 >> 8) & 0xff) as usize]
                ^ TE3[(s0 & 0xff) as usize]
                ^ rk[5];
            t2 = TE0[(s2 >> 24) as usize]
                ^ TE1[((s3 >> 16) & 0xff) as usize]
                ^ TE2[((s0 >> 8) & 0xff) as usize]
                ^ TE3[(s1 & 0xff) as usize]
                ^ rk[6];
            t3 = TE0[(s3 >> 24) as usize]
                ^ TE1[((s0 >> 16) & 0xff) as usize]
                ^ TE2[((s1 >> 8) & 0xff) as usize]
                ^ TE3[(s2 & 0xff) as usize]
                ^ rk[7];

            rk = &rk[8..];
            r -= 1;

            if r == 0 {
                break;
            }

            s0 = TE0[(t0 >> 24) as usize]
                ^ TE1[((t1 >> 16) & 0xff) as usize]
                ^ TE2[((t2 >> 8) & 0xff) as usize]
                ^ TE3[(t3 & 0xff) as usize]
                ^ rk[0];
            s1 = TE0[(t1 >> 24) as usize]
                ^ TE1[((t2 >> 16) & 0xff) as usize]
                ^ TE2[((t3 >> 8) & 0xff) as usize]
                ^ TE3[(t0 & 0xff) as usize]
                ^ rk[1];
            s2 = TE0[(t2 >> 24) as usize]
                ^ TE1[((t3 >> 16) & 0xff) as usize]
                ^ TE2[((t0 >> 8) & 0xff) as usize]
                ^ TE3[(t1 & 0xff) as usize]
                ^ rk[2];
            s3 = TE0[(t3 >> 24) as usize]
                ^ TE1[((t0 >> 16) & 0xff) as usize]
                ^ TE2[((t1 >> 8) & 0xff) as usize]
                ^ TE3[(t2 & 0xff) as usize]
                ^ rk[3];
        }
    }

    s0 = (TE4[(t0 >> 24) as usize] & 0xff000000)
        ^ (TE4[(t1 >> 16) as usize & 0xff] & 0x00ff0000)
        ^ (TE4[(t2 >> 8) as usize & 0xff] & 0x0000ff00)
        ^ (TE4[(t3) as usize & 0xff] & 0x000000ff)
        ^ rk[0];
    put_u32(&mut ct[0..4], s0);

    s1 = (TE4[(t1 >> 24) as usize] & 0xff000000)
        ^ (TE4[(t2 >> 16) as usize & 0xff] & 0x00ff0000)
        ^ (TE4[(t3 >> 8) as usize & 0xff] & 0x0000ff00)
        ^ (TE4[(t0) as usize & 0xff] & 0x000000ff)
        ^ rk[1];

    put_u32(&mut ct[4..8], s1);

    s2 = (TE4[(t2 >> 24) as usize] & 0xff000000)
        ^ (TE4[(t3 >> 16) as usize & 0xff] & 0x00ff0000)
        ^ (TE4[(t0 >> 8) as usize & 0xff] & 0x0000ff00)
        ^ (TE4[(t1) as usize & 0xff] & 0x000000ff)
        ^ rk[2];

    put_u32(&mut ct[8..12], s2);

    s3 = (TE4[(t3 >> 24) as usize] & 0xff000000)
        ^ (TE4[(t0 >> 16) as usize & 0xff] & 0x00ff0000)
        ^ (TE4[(t1 >> 8) as usize & 0xff] & 0x0000ff00)
        ^ (TE4[(t2) as usize & 0xff] & 0x000000ff)
        ^ rk[3];
    put_u32(&mut ct[12..16], s3);
}

pub fn rijndael_set_key_enc_only(ctx: &mut RijndaelCtx, key: &[u8], bits: i32) -> i32 {
    let mut rounds: i32 = 0;
    rounds = rijndaelKeySetupEnc(&mut ctx.ek, key, bits);
    if rounds == 0 {
        return -1;
    }
    ctx.nr = rounds;
    ctx.enc_only = 1;
    return 0;
}

pub fn rijndael_set_key(ctx: &mut RijndaelCtx, key: &[u8], bits: i32) -> i32 {
    let rounds = rijndaelKeySetupEnc(&mut ctx.ek, key, bits);
    if rounds == 0 {
        return -1;
    }
    if rijndaelKeySetupDec(&mut ctx.dk, key, bits) != rounds {
        return -1;
    }
    ctx.nr = rounds;
    ctx.enc_only = 0;
    return 0;
}

pub fn rijndael_decrypt(ctx: &RijndaelCtx, src: &[u8], dst: &mut [u8]) {
    rijndaelDecrypt(
        &ctx.dk,
        ctx.nr,
        src.try_into().unwrap(),
        dst.try_into().unwrap(),
    );
}

pub fn rijndael_encrypt(ctx: &RijndaelCtx, src: &[u8], dst: &mut [u8]) {
    rijndaelEncrypt(
        &ctx.ek,
        ctx.nr,
        src.try_into().unwrap(),
        dst.try_into().unwrap(),
    );
}

pub fn AES_set_key(ctx: &mut AesCtx, key: &[u8], bits: i32) -> i32 {
    let mut ctx: RijndaelCtx = (*ctx).into();
    return rijndael_set_key(&mut ctx, key, bits);
}

pub fn AES_decrypt(ctx: &AesCtx, src: &[u8], dst: &mut [u8]) {
    return rijndaelDecrypt(
        &ctx.dk,
        ctx.nr,
        src.try_into().unwrap(),
        dst.try_into().unwrap(),
    );
}

pub fn AES_encrypt(ctx: &AesCtx, src: &[u8], dst: &mut [u8]) {
    return rijndaelEncrypt(
        &ctx.ek,
        ctx.nr,
        src.try_into().unwrap(),
        dst.try_into().unwrap(),
    );
}

pub fn xor_128(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
}

pub fn AES_cbc_encrypt(ctx: &AesCtx, src: &[u8], dst: &mut [u8], size: usize) {
    let mut block_buff = [0u8; 16];

    for i in (0..size).step_by(16) {
        // step 1: copy block to dst
        dst[i..(i + 16)].copy_from_slice(&src[i..(i + 16)]);

        // step 2: XOR with previous block
        if i != 0 {
            let prev_source :[u8;16] = dst[i..(i + 16)].try_into().unwrap();
            xor_128(
                &prev_source,
                &block_buff,
                &mut dst[i..(i + 16)],
            );
        }

        // step 3: encrypt the block -> it lands in block buffer
        AES_encrypt(ctx, &dst[i..(i + 16)], &mut block_buff);

        // step 4: copy back the encrypted block to destination
        dst[i..(i + 16)].copy_from_slice(&block_buff);
    }
}

pub fn AES_cbc_decrypt(ctx: &AesCtx, src: &[u8], dst: &mut [u8], size: usize) {
    let mut block_buff = [0u8; 16];
    let mut block_buff_previous = [0u8; 16];

    block_buff.copy_from_slice(&src[..16]);
    block_buff_previous.copy_from_slice(&src[..16]);
    AES_decrypt(ctx, &src[..16], &mut dst[..16]);

    for i in (16..size).step_by(16) {
        let current_block = &src[i..(i + 16)];
        block_buff.copy_from_slice(current_block);
        dst[i..(i + 16)].copy_from_slice(current_block);

        let csrc_temp : [u8; 16] = dst[i..(i + 16)].try_into().unwrap();
        AES_decrypt(ctx,&csrc_temp, &mut dst[i..(i + 16)]);
        
        let csrc_xor_temp : [u8;16] = dst[i..(i + 16)].try_into().unwrap();
        xor_128(
            &csrc_xor_temp,
            &block_buff_previous,
            &mut dst[i..(i + 16)],
        );

        block_buff_previous.copy_from_slice(&block_buff);
    }
}

pub fn leftshift_onebit(input: &mut [u8], output: &mut [u8]) {
    let mut overflow: u8 = 0;

    for i in (0..16).rev() {
        output[i] = input[i] << 1;
        output[i] |= overflow;
        overflow = if input[i] & 0x80 != 0 { 1 } else { 0 };
    }
}

pub fn generate_subkey(ctx: &AesCtx, mut k1: &mut [u8], mut k2: &mut [u8]) {
    let mut l = [0u8; 16];
    let z = [0u8; 16];
    let mut tmp = [0u8; 16];

    AES_encrypt(ctx, &z, &mut l);

    if l[0] & 0x80 == 0 {
        leftshift_onebit(&mut l, &mut k1);
    } else {
        leftshift_onebit(&mut l, &mut tmp);
        xor_128(&tmp, &CONST_RB, k1);
    }

    if k1[0] & 0x80 == 0 {
        leftshift_onebit(&mut k1, &mut k2);
    } else {
        leftshift_onebit(&mut k1, &mut tmp);
        xor_128(&tmp, &CONST_RB, k2);
    }
}

pub fn padding(lastb: &[u8], pad: &mut [u8], length: usize) {
    for j in 0..16 {
        if j < length {
            pad[j] = lastb[j];
        } else if j == length {
            pad[j] = 0x80;
        } else {
            pad[j] = 0x00;
        }
    }
}

pub fn AES_CMAC(ctx: &mut AesCtx, input: &[u8], length: usize, mac: &mut [u8]) {
    let mut x = [0u8; 16];
    let mut y = [0u8; 16];
    let mut m_last = [0u8; 16];
    let mut padded = [0u8; 16];
    let mut k1 = [0u8; 16];
    let mut k2 = [0u8; 16];

    generate_subkey(ctx, &mut k1, &mut k2);

    let n = (length + 15) / 16;

    let flag = if n == 0 {
        1
    } else if length % 16 == 0 {
        2
    } else {
        0
    };

    if flag == 2 {
        xor_128(&input[16 * (n - 1)..], &k1, &mut m_last);
    } else {
        padding(&input[16 * (n - 1)..], &mut padded, length % 16);
        xor_128(&padded, &k2, &mut m_last);
    }

    for i in 0..16 {
        x[i] = 0;
    }

    for i in 0..n - 1 {
        xor_128(&x, &input[16 * i..], &mut y);
        AES_encrypt(ctx, &y, &mut x);
    }

    xor_128(&x, &m_last, &mut y);
    AES_encrypt(ctx, &y, &mut x);

    for i in 0..16 {
        mac[i] = x[i];
    }
}

// sha1 implementation
pub fn sha1_circular_shift(bits: u32, word: u32) -> u32 {
    ((word << bits) & 0xFFFFFFFF) | (word >> (32 - bits))
}

pub struct Sha1Context {
    message_digest: [u32; 5], // Message Digest (output)
    length_low: u32,          // Message length in bits
    length_high: u32,         // Message length in bits
    message_block: [u8; 64],  // 512-bit message blocks
    message_block_index: i32, // Index into message block array
    computed: i32,            // Is the digest computed?
    corrupted: i32,           // Is the message digest corrupted?
}

// Function prototypes
//fn SHA1ProcessMessageBlock(context: &mut SHA1Context);
//fn SHA1PadMessage(context: &mut SHA1Context);

// SHA1Reset function
pub fn sha1_reset(context: &mut Sha1Context) {
    context.length_low = 0;
    context.length_high = 0;
    context.message_block_index = 0;
    context.message_digest[0] = 0x67452301;
    context.message_digest[1] = 0xEFCDAB89;
    context.message_digest[2] = 0x98BADCFE;
    context.message_digest[3] = 0x10325476;
    context.message_digest[4] = 0xC3D2E1F0;

    context.computed = 0;
    context.corrupted = 0;
}


/*
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array within the SHA1Context provided
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *
 *  Returns:
 *      1 if successful, 0 if it failed.
 *
 *  Comments:
 *
 */
pub fn sha1_result(context: &mut Sha1Context) -> i32 {
    if context.corrupted != 0 {
        return 0;
    }

    if context.computed == 0 {
        sha1_pad_message(context);
        context.computed = 1;
    }

    return 1
}

pub fn sha1_input(context: &mut Sha1Context, message_array: &[u8], length: usize) {
    if length == 0 {
        return;
    }

    // if we go to c standard if(int) is considered anything that not 0 is true and 0 is false
    // correct me on this one
    if context.computed != 0 || context.corrupted != 0{
        context.corrupted = 1;
        return;
    }

    for &byte in message_array.iter().take(length) {
        context.message_block[context.message_block_index as usize] = byte;

        context.length_low = context.length_low.wrapping_add(8);
        context.length_low &= 0xFFFFFFFF; // Force it to 32 bits
        if context.length_low == 0 {
            context.length_high = context.length_high.wrapping_add(1);
            context.length_high &= 0xFFFFFFFF; // Force it to 32 bits
            if context.length_high == 0 {
                // Message is too long
                context.corrupted = 1;
            }
        }

        context.message_block_index =  context.message_block_index + 1;

        if context.message_block_index == 64 {
            sha1_process_message_block(context);
        }
    }
}

fn sha1_process_message_block(context: &mut Sha1Context) {
    const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
    let t: usize;
    let mut temp: u32;
    let mut W: [u32; 80] = [0; 80];
    let mut A: u32;
    let mut B: u32;
    let mut C: u32;
    let mut D: u32;
    let mut E: u32;

    for t in 0..16 {
        W[t] = (context.message_block[t * 4] as u32) << 24
            | (context.message_block[t * 4 + 1] as u32) << 16
            | (context.message_block[t * 4 + 2] as u32) << 8
            | (context.message_block[t * 4 + 3] as u32);
    }

    for t in 16..80 {
        W[t] = sha1_circular_shift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
    }

    A = context.message_digest[0];
    B = context.message_digest[1];
    C = context.message_digest[2];
    D = context.message_digest[3];
    E = context.message_digest[4];

    for t in 0..20 {
        temp = sha1_circular_shift(5, A) + ((B & C) | ((!B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = sha1_circular_shift(30, B);
        B = A;
        A = temp;
    }

    for t in 20..40 {
        temp = sha1_circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = sha1_circular_shift(30, B);
        B = A;
        A = temp;
    }

    for t in 40..60 {
        temp = sha1_circular_shift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = sha1_circular_shift(30, B);
        B = A;
        A = temp;
    }

    for t in 60..80 {
        temp = sha1_circular_shift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = sha1_circular_shift(30, B);
        B = A;
        A = temp;
    }

    context.message_digest[0] = (context.message_digest[0] + A) & 0xFFFFFFFF;
    context.message_digest[1] = (context.message_digest[1] + B) & 0xFFFFFFFF;
    context.message_digest[2] = (context.message_digest[2] + C) & 0xFFFFFFFF;
    context.message_digest[3] = (context.message_digest[3] + D) & 0xFFFFFFFF;
    context.message_digest[4] = (context.message_digest[4] + E) & 0xFFFFFFFF;
    context.message_block_index = 0;
}

fn sha1_pad_message(context: &mut Sha1Context) {
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if context.message_block_index > 55 {
        context.message_block[context.message_block_index as usize] = 0x80;
        context.message_block_index = context.message_block_index + 1;
        while context.message_block_index < 64 {
            context.message_block[context.message_block_index as usize] = 0;
            context.message_block_index = context.message_block_index + 1;
        }

        sha1_process_message_block(context);

        while context.message_block_index < 56 {
            context.message_block[context.message_block_index as usize] = 0;
            context.message_block_index = context.message_block_index + 1;
        }
    } else {
        context.message_block[context.message_block_index as usize] = 0x80;
        context.message_block_index = context.message_block_index + 1;
        while context.message_block_index < 56 {
            context.message_block[context.message_block_index as usize] = 0;
            context.message_block_index = context.message_block_index + 1;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context.message_block[56] = (context.length_high >> 24) as u8;
    context.message_block[57] = (context.length_high >> 16) as u8;
    context.message_block[58] = (context.length_high >> 8) as u8;
    context.message_block[59] = context.length_high as u8;
    context.message_block[60] = (context.length_low >> 24) as u8;
    context.message_block[61] = (context.length_low >> 16) as u8;
    context.message_block[62] = (context.length_low >> 8) as u8;
    context.message_block[63] = context.length_low as u8;

    sha1_process_message_block(context);
}

pub fn aes_cmac_forge(ctx: &mut AesCtx, input: &mut [u8], length: i32, forge: &mut [u8]) {
    let mut X: [u8; 16] = [0; 16];
    let mut Y: [u8; 16] = [0; 16];
    let mut M_last: [u8; 16] = [0; 16];
    let mut padded: [u8; 16] = [0; 16];
    let mut K1: [u8; 16] = [0; 16];
    let mut K2: [u8; 16] = [0; 16];

    generate_subkey(ctx, &mut K1, &mut K2);

    let n: i32 = (length + 15) / 16; // n is the number of rounds

    let flag: bool;
    if n == 0 {
        flag = false;
    } else {
        flag = length % 16 == 0; // last block is a complete block
    }

    if flag {
        // does this one correct its should return array [u8] insteand pointer into u8 ...
        xor_128(&input[16 * (n as usize - 1)..], &K1, &mut M_last);
    } else {
        padding(&input[16 * (n as usize - 1)..], &mut padded, length as usize % 16);
        xor_128(&padded, &K2, &mut M_last);
    }

    X.fill(0);

    for i in 0..(n - 1) {
        xor_128(&X, &input[16 * (i as usize)..], &mut Y);
        AES_encrypt(ctx, &Y, &mut X);
    }

    xor_128(&X, &M_last, &mut Y);

    AES_decrypt(ctx, forge, &mut X);
    xor_128(&mut X, &Y, forge);
    xor_128(forge, &input[16 * (n as usize - 1)..], &mut Y);

    for i in 0..16 {
        input[(16 * (n as usize - 1)) + i] = Y[i];
    }
}
