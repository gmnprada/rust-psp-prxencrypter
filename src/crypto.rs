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
    pub Nr: i32,
    pub ek: [u32; 4 * (AES_MAXROUNDS + 1)],
    pub dk: [u32; 4 * (AES_MAXROUNDS + 1)],
}

impl From<RijndaelCtx> for AES_ctx {
    fn from(val: RijndaelCtx) -> AES_ctx {
        AES_ctx {
            enc_only: val.enc_only,
            Nr: val.Nr,
            ek: val.ek,
            dk: val.dk,
        }
    }
}
pub type PwuAESContextBuffer = RijndaelCtx;

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
#[repr(C)]
pub struct AES_ctx {
    pub enc_only: i32,
    pub Nr: i32,
    pub ek: [u32; 4 * (AES_MAXROUNDS + 1)],
    pub dk: [u32; 4 * (AES_MAXROUNDS + 1)],
}

impl From<AES_ctx> for RijndaelCtx {
    fn from(val: AES_ctx) -> RijndaelCtx {
        RijndaelCtx {
            enc_only: val.enc_only,
            Nr: val.Nr,
            ek: val.ek,
            dk: val.dk,
        }
    }
}

// should return unsigned 32 bits
static TE0: [u32; 256] = [
    0xc66363a5u32,
    0xf87c7c84u32,
    0xee777799u32,
    0xf67b7b8du32,
    0xfff2f20du32,
    0xd66b6bbdu32,
    0xde6f6fb1u32,
    0x91c5c554u32,
    0x60303050u32,
    0x02010103u32,
    0xce6767a9u32,
    0x562b2b7du32,
    0xe7fefe19u32,
    0xb5d7d762u32,
    0x4dababe6u32,
    0xec76769au32,
    0x8fcaca45u32,
    0x1f82829du32,
    0x89c9c940u32,
    0xfa7d7d87u32,
    0xeffafa15u32,
    0xb25959ebu32,
    0x8e4747c9u32,
    0xfbf0f00bu32,
    0x41adadecu32,
    0xb3d4d467u32,
    0x5fa2a2fdu32,
    0x45afafeau32,
    0x239c9cbfu32,
    0x53a4a4f7u32,
    0xe4727296u32,
    0x9bc0c05bu32,
    0x75b7b7c2u32,
    0xe1fdfd1cu32,
    0x3d9393aeu32,
    0x4c26266au32,
    0x6c36365au32,
    0x7e3f3f41u32,
    0xf5f7f702u32,
    0x83cccc4fu32,
    0x6834345cu32,
    0x51a5a5f4u32,
    0xd1e5e534u32,
    0xf9f1f108u32,
    0xe2717193u32,
    0xabd8d873u32,
    0x62313153u32,
    0x2a15153fu32,
    0x0804040cu32,
    0x95c7c752u32,
    0x46232365u32,
    0x9dc3c35eu32,
    0x30181828u32,
    0x379696a1u32,
    0x0a05050fu32,
    0x2f9a9ab5u32,
    0x0e070709u32,
    0x24121236u32,
    0x1b80809bu32,
    0xdfe2e23du32,
    0xcdebeb26u32,
    0x4e272769u32,
    0x7fb2b2cdu32,
    0xea75759fu32,
    0x1209091bu32,
    0x1d83839eu32,
    0x582c2c74u32,
    0x341a1a2eu32,
    0x361b1b2du32,
    0xdc6e6eb2u32,
    0xb45a5aeeu32,
    0x5ba0a0fbu32,
    0xa45252f6u32,
    0x763b3b4du32,
    0xb7d6d661u32,
    0x7db3b3ceu32,
    0x5229297bu32,
    0xdde3e33eu32,
    0x5e2f2f71u32,
    0x13848497u32,
    0xa65353f5u32,
    0xb9d1d168u32,
    0x00000000u32,
    0xc1eded2cu32,
    0x40202060u32,
    0xe3fcfc1fu32,
    0x79b1b1c8u32,
    0xb65b5bedu32,
    0xd46a6abeu32,
    0x8dcbcb46u32,
    0x67bebed9u32,
    0x7239394bu32,
    0x944a4adeu32,
    0x984c4cd4u32,
    0xb05858e8u32,
    0x85cfcf4au32,
    0xbbd0d06bu32,
    0xc5efef2au32,
    0x4faaaae5u32,
    0xedfbfb16u32,
    0x864343c5u32,
    0x9a4d4dd7u32,
    0x66333355u32,
    0x11858594u32,
    0x8a4545cfu32,
    0xe9f9f910u32,
    0x04020206u32,
    0xfe7f7f81u32,
    0xa05050f0u32,
    0x783c3c44u32,
    0x259f9fbau32,
    0x4ba8a8e3u32,
    0xa25151f3u32,
    0x5da3a3feu32,
    0x804040c0u32,
    0x058f8f8au32,
    0x3f9292adu32,
    0x219d9dbcu32,
    0x70383848u32,
    0xf1f5f504u32,
    0x63bcbcdfu32,
    0x77b6b6c1u32,
    0xafdada75u32,
    0x42212163u32,
    0x20101030u32,
    0xe5ffff1au32,
    0xfdf3f30eu32,
    0xbfd2d26du32,
    0x81cdcd4cu32,
    0x180c0c14u32,
    0x26131335u32,
    0xc3ecec2fu32,
    0xbe5f5fe1u32,
    0x359797a2u32,
    0x884444ccu32,
    0x2e171739u32,
    0x93c4c457u32,
    0x55a7a7f2u32,
    0xfc7e7e82u32,
    0x7a3d3d47u32,
    0xc86464acu32,
    0xba5d5de7u32,
    0x3219192bu32,
    0xe6737395u32,
    0xc06060a0u32,
    0x19818198u32,
    0x9e4f4fd1u32,
    0xa3dcdc7fu32,
    0x44222266u32,
    0x542a2a7eu32,
    0x3b9090abu32,
    0x0b888883u32,
    0x8c4646cau32,
    0xc7eeee29u32,
    0x6bb8b8d3u32,
    0x2814143cu32,
    0xa7dede79u32,
    0xbc5e5ee2u32,
    0x160b0b1du32,
    0xaddbdb76u32,
    0xdbe0e03bu32,
    0x64323256u32,
    0x743a3a4eu32,
    0x140a0a1eu32,
    0x924949dbu32,
    0x0c06060au32,
    0x4824246cu32,
    0xb85c5ce4u32,
    0x9fc2c25du32,
    0xbdd3d36eu32,
    0x43acacefu32,
    0xc46262a6u32,
    0x399191a8u32,
    0x319595a4u32,
    0xd3e4e437u32,
    0xf279798bu32,
    0xd5e7e732u32,
    0x8bc8c843u32,
    0x6e373759u32,
    0xda6d6db7u32,
    0x018d8d8cu32,
    0xb1d5d564u32,
    0x9c4e4ed2u32,
    0x49a9a9e0u32,
    0xd86c6cb4u32,
    0xac5656fau32,
    0xf3f4f407u32,
    0xcfeaea25u32,
    0xca6565afu32,
    0xf47a7a8eu32,
    0x47aeaee9u32,
    0x10080818u32,
    0x6fbabad5u32,
    0xf0787888u32,
    0x4a25256fu32,
    0x5c2e2e72u32,
    0x381c1c24u32,
    0x57a6a6f1u32,
    0x73b4b4c7u32,
    0x97c6c651u32,
    0xcbe8e823u32,
    0xa1dddd7cu32,
    0xe874749cu32,
    0x3e1f1f21u32,
    0x964b4bddu32,
    0x61bdbddcu32,
    0x0d8b8b86u32,
    0x0f8a8a85u32,
    0xe0707090u32,
    0x7c3e3e42u32,
    0x71b5b5c4u32,
    0xcc6666aau32,
    0x904848d8u32,
    0x06030305u32,
    0xf7f6f601u32,
    0x1c0e0e12u32,
    0xc26161a3u32,
    0x6a35355fu32,
    0xae5757f9u32,
    0x69b9b9d0u32,
    0x17868691u32,
    0x99c1c158u32,
    0x3a1d1d27u32,
    0x279e9eb9u32,
    0xd9e1e138u32,
    0xebf8f813u32,
    0x2b9898b3u32,
    0x22111133u32,
    0xd26969bbu32,
    0xa9d9d970u32,
    0x078e8e89u32,
    0x339494a7u32,
    0x2d9b9bb6u32,
    0x3c1e1e22u32,
    0x15878792u32,
    0xc9e9e920u32,
    0x87cece49u32,
    0xaa5555ffu32,
    0x50282878u32,
    0xa5dfdf7au32,
    0x038c8c8fu32,
    0x59a1a1f8u32,
    0x09898980u32,
    0x1a0d0d17u32,
    0x65bfbfdau32,
    0xd7e6e631u32,
    0x844242c6u32,
    0xd06868b8u32,
    0x824141c3u32,
    0x299999b0u32,
    0x5a2d2d77u32,
    0x1e0f0f11u32,
    0x7bb0b0cbu32,
    0xa85454fcu32,
    0x6dbbbbd6u32,
    0x2c16163au32,
];

static TE1: [u32; 256] = [
    0xa5c66363u32,
    0x84f87c7cu32,
    0x99ee7777u32,
    0x8df67b7bu32,
    0x0dfff2f2u32,
    0xbdd66b6bu32,
    0xb1de6f6fu32,
    0x5491c5c5u32,
    0x50603030u32,
    0x03020101u32,
    0xa9ce6767u32,
    0x7d562b2bu32,
    0x19e7fefeu32,
    0x62b5d7d7u32,
    0xe64dababu32,
    0x9aec7676u32,
    0x458fcacau32,
    0x9d1f8282u32,
    0x4089c9c9u32,
    0x87fa7d7du32,
    0x15effafau32,
    0xebb25959u32,
    0xc98e4747u32,
    0x0bfbf0f0u32,
    0xec41adadu32,
    0x67b3d4d4u32,
    0xfd5fa2a2u32,
    0xea45afafu32,
    0xbf239c9cu32,
    0xf753a4a4u32,
    0x96e47272u32,
    0x5b9bc0c0u32,
    0xc275b7b7u32,
    0x1ce1fdfdu32,
    0xae3d9393u32,
    0x6a4c2626u32,
    0x5a6c3636u32,
    0x417e3f3fu32,
    0x02f5f7f7u32,
    0x4f83ccccu32,
    0x5c683434u32,
    0xf451a5a5u32,
    0x34d1e5e5u32,
    0x08f9f1f1u32,
    0x93e27171u32,
    0x73abd8d8u32,
    0x53623131u32,
    0x3f2a1515u32,
    0x0c080404u32,
    0x5295c7c7u32,
    0x65462323u32,
    0x5e9dc3c3u32,
    0x28301818u32,
    0xa1379696u32,
    0x0f0a0505u32,
    0xb52f9a9au32,
    0x090e0707u32,
    0x36241212u32,
    0x9b1b8080u32,
    0x3ddfe2e2u32,
    0x26cdebebu32,
    0x694e2727u32,
    0xcd7fb2b2u32,
    0x9fea7575u32,
    0x1b120909u32,
    0x9e1d8383u32,
    0x74582c2cu32,
    0x2e341a1au32,
    0x2d361b1bu32,
    0xb2dc6e6eu32,
    0xeeb45a5au32,
    0xfb5ba0a0u32,
    0xf6a45252u32,
    0x4d763b3bu32,
    0x61b7d6d6u32,
    0xce7db3b3u32,
    0x7b522929u32,
    0x3edde3e3u32,
    0x715e2f2fu32,
    0x97138484u32,
    0xf5a65353u32,
    0x68b9d1d1u32,
    0x00000000u32,
    0x2cc1ededu32,
    0x60402020u32,
    0x1fe3fcfcu32,
    0xc879b1b1u32,
    0xedb65b5bu32,
    0xbed46a6au32,
    0x468dcbcbu32,
    0xd967bebeu32,
    0x4b723939u32,
    0xde944a4au32,
    0xd4984c4cu32,
    0xe8b05858u32,
    0x4a85cfcfu32,
    0x6bbbd0d0u32,
    0x2ac5efefu32,
    0xe54faaaau32,
    0x16edfbfbu32,
    0xc5864343u32,
    0xd79a4d4du32,
    0x55663333u32,
    0x94118585u32,
    0xcf8a4545u32,
    0x10e9f9f9u32,
    0x06040202u32,
    0x81fe7f7fu32,
    0xf0a05050u32,
    0x44783c3cu32,
    0xba259f9fu32,
    0xe34ba8a8u32,
    0xf3a25151u32,
    0xfe5da3a3u32,
    0xc0804040u32,
    0x8a058f8fu32,
    0xad3f9292u32,
    0xbc219d9du32,
    0x48703838u32,
    0x04f1f5f5u32,
    0xdf63bcbcu32,
    0xc177b6b6u32,
    0x75afdadau32,
    0x63422121u32,
    0x30201010u32,
    0x1ae5ffffu32,
    0x0efdf3f3u32,
    0x6dbfd2d2u32,
    0x4c81cdcdu32,
    0x14180c0cu32,
    0x35261313u32,
    0x2fc3ececu32,
    0xe1be5f5fu32,
    0xa2359797u32,
    0xcc884444u32,
    0x392e1717u32,
    0x5793c4c4u32,
    0xf255a7a7u32,
    0x82fc7e7eu32,
    0x477a3d3du32,
    0xacc86464u32,
    0xe7ba5d5du32,
    0x2b321919u32,
    0x95e67373u32,
    0xa0c06060u32,
    0x98198181u32,
    0xd19e4f4fu32,
    0x7fa3dcdcu32,
    0x66442222u32,
    0x7e542a2au32,
    0xab3b9090u32,
    0x830b8888u32,
    0xca8c4646u32,
    0x29c7eeeeu32,
    0xd36bb8b8u32,
    0x3c281414u32,
    0x79a7dedeu32,
    0xe2bc5e5eu32,
    0x1d160b0bu32,
    0x76addbdbu32,
    0x3bdbe0e0u32,
    0x56643232u32,
    0x4e743a3au32,
    0x1e140a0au32,
    0xdb924949u32,
    0x0a0c0606u32,
    0x6c482424u32,
    0xe4b85c5cu32,
    0x5d9fc2c2u32,
    0x6ebdd3d3u32,
    0xef43acacu32,
    0xa6c46262u32,
    0xa8399191u32,
    0xa4319595u32,
    0x37d3e4e4u32,
    0x8bf27979u32,
    0x32d5e7e7u32,
    0x438bc8c8u32,
    0x596e3737u32,
    0xb7da6d6du32,
    0x8c018d8du32,
    0x64b1d5d5u32,
    0xd29c4e4eu32,
    0xe049a9a9u32,
    0xb4d86c6cu32,
    0xfaac5656u32,
    0x07f3f4f4u32,
    0x25cfeaeau32,
    0xafca6565u32,
    0x8ef47a7au32,
    0xe947aeaeu32,
    0x18100808u32,
    0xd56fbabau32,
    0x88f07878u32,
    0x6f4a2525u32,
    0x725c2e2eu32,
    0x24381c1cu32,
    0xf157a6a6u32,
    0xc773b4b4u32,
    0x5197c6c6u32,
    0x23cbe8e8u32,
    0x7ca1ddddu32,
    0x9ce87474u32,
    0x213e1f1fu32,
    0xdd964b4bu32,
    0xdc61bdbdu32,
    0x860d8b8bu32,
    0x850f8a8au32,
    0x90e07070u32,
    0x427c3e3eu32,
    0xc471b5b5u32,
    0xaacc6666u32,
    0xd8904848u32,
    0x05060303u32,
    0x01f7f6f6u32,
    0x121c0e0eu32,
    0xa3c26161u32,
    0x5f6a3535u32,
    0xf9ae5757u32,
    0xd069b9b9u32,
    0x91178686u32,
    0x5899c1c1u32,
    0x273a1d1du32,
    0xb9279e9eu32,
    0x38d9e1e1u32,
    0x13ebf8f8u32,
    0xb32b9898u32,
    0x33221111u32,
    0xbbd26969u32,
    0x70a9d9d9u32,
    0x89078e8eu32,
    0xa7339494u32,
    0xb62d9b9bu32,
    0x223c1e1eu32,
    0x92158787u32,
    0x20c9e9e9u32,
    0x4987ceceu32,
    0xffaa5555u32,
    0x78502828u32,
    0x7aa5dfdfu32,
    0x8f038c8cu32,
    0xf859a1a1u32,
    0x80098989u32,
    0x171a0d0du32,
    0xda65bfbfu32,
    0x31d7e6e6u32,
    0xc6844242u32,
    0xb8d06868u32,
    0xc3824141u32,
    0xb0299999u32,
    0x775a2d2du32,
    0x111e0f0fu32,
    0xcb7bb0b0u32,
    0xfca85454u32,
    0xd66dbbbbu32,
    0x3a2c1616u32,
];

static TE2: [u32; 256] = [
    0x63a5c663u32,
    0x7c84f87cu32,
    0x7799ee77u32,
    0x7b8df67bu32,
    0xf20dfff2u32,
    0x6bbdd66bu32,
    0x6fb1de6fu32,
    0xc55491c5u32,
    0x30506030u32,
    0x01030201u32,
    0x67a9ce67u32,
    0x2b7d562bu32,
    0xfe19e7feu32,
    0xd762b5d7u32,
    0xabe64dabu32,
    0x769aec76u32,
    0xca458fcau32,
    0x829d1f82u32,
    0xc94089c9u32,
    0x7d87fa7du32,
    0xfa15effau32,
    0x59ebb259u32,
    0x47c98e47u32,
    0xf00bfbf0u32,
    0xadec41adu32,
    0xd467b3d4u32,
    0xa2fd5fa2u32,
    0xafea45afu32,
    0x9cbf239cu32,
    0xa4f753a4u32,
    0x7296e472u32,
    0xc05b9bc0u32,
    0xb7c275b7u32,
    0xfd1ce1fdu32,
    0x93ae3d93u32,
    0x266a4c26u32,
    0x365a6c36u32,
    0x3f417e3fu32,
    0xf702f5f7u32,
    0xcc4f83ccu32,
    0x345c6834u32,
    0xa5f451a5u32,
    0xe534d1e5u32,
    0xf108f9f1u32,
    0x7193e271u32,
    0xd873abd8u32,
    0x31536231u32,
    0x153f2a15u32,
    0x040c0804u32,
    0xc75295c7u32,
    0x23654623u32,
    0xc35e9dc3u32,
    0x18283018u32,
    0x96a13796u32,
    0x050f0a05u32,
    0x9ab52f9au32,
    0x07090e07u32,
    0x12362412u32,
    0x809b1b80u32,
    0xe23ddfe2u32,
    0xeb26cdebu32,
    0x27694e27u32,
    0xb2cd7fb2u32,
    0x759fea75u32,
    0x091b1209u32,
    0x839e1d83u32,
    0x2c74582cu32,
    0x1a2e341au32,
    0x1b2d361bu32,
    0x6eb2dc6eu32,
    0x5aeeb45au32,
    0xa0fb5ba0u32,
    0x52f6a452u32,
    0x3b4d763bu32,
    0xd661b7d6u32,
    0xb3ce7db3u32,
    0x297b5229u32,
    0xe33edde3u32,
    0x2f715e2fu32,
    0x84971384u32,
    0x53f5a653u32,
    0xd168b9d1u32,
    0x00000000u32,
    0xed2cc1edu32,
    0x20604020u32,
    0xfc1fe3fcu32,
    0xb1c879b1u32,
    0x5bedb65bu32,
    0x6abed46au32,
    0xcb468dcbu32,
    0xbed967beu32,
    0x394b7239u32,
    0x4ade944au32,
    0x4cd4984cu32,
    0x58e8b058u32,
    0xcf4a85cfu32,
    0xd06bbbd0u32,
    0xef2ac5efu32,
    0xaae54faau32,
    0xfb16edfbu32,
    0x43c58643u32,
    0x4dd79a4du32,
    0x33556633u32,
    0x85941185u32,
    0x45cf8a45u32,
    0xf910e9f9u32,
    0x02060402u32,
    0x7f81fe7fu32,
    0x50f0a050u32,
    0x3c44783cu32,
    0x9fba259fu32,
    0xa8e34ba8u32,
    0x51f3a251u32,
    0xa3fe5da3u32,
    0x40c08040u32,
    0x8f8a058fu32,
    0x92ad3f92u32,
    0x9dbc219du32,
    0x38487038u32,
    0xf504f1f5u32,
    0xbcdf63bcu32,
    0xb6c177b6u32,
    0xda75afdau32,
    0x21634221u32,
    0x10302010u32,
    0xff1ae5ffu32,
    0xf30efdf3u32,
    0xd26dbfd2u32,
    0xcd4c81cdu32,
    0x0c14180cu32,
    0x13352613u32,
    0xec2fc3ecu32,
    0x5fe1be5fu32,
    0x97a23597u32,
    0x44cc8844u32,
    0x17392e17u32,
    0xc45793c4u32,
    0xa7f255a7u32,
    0x7e82fc7eu32,
    0x3d477a3du32,
    0x64acc864u32,
    0x5de7ba5du32,
    0x192b3219u32,
    0x7395e673u32,
    0x60a0c060u32,
    0x81981981u32,
    0x4fd19e4fu32,
    0xdc7fa3dcu32,
    0x22664422u32,
    0x2a7e542au32,
    0x90ab3b90u32,
    0x88830b88u32,
    0x46ca8c46u32,
    0xee29c7eeu32,
    0xb8d36bb8u32,
    0x143c2814u32,
    0xde79a7deu32,
    0x5ee2bc5eu32,
    0x0b1d160bu32,
    0xdb76addbu32,
    0xe03bdbe0u32,
    0x32566432u32,
    0x3a4e743au32,
    0x0a1e140au32,
    0x49db9249u32,
    0x060a0c06u32,
    0x246c4824u32,
    0x5ce4b85cu32,
    0xc25d9fc2u32,
    0xd36ebdd3u32,
    0xacef43acu32,
    0x62a6c462u32,
    0x91a83991u32,
    0x95a43195u32,
    0xe437d3e4u32,
    0x798bf279u32,
    0xe732d5e7u32,
    0xc8438bc8u32,
    0x37596e37u32,
    0x6db7da6du32,
    0x8d8c018du32,
    0xd564b1d5u32,
    0x4ed29c4eu32,
    0xa9e049a9u32,
    0x6cb4d86cu32,
    0x56faac56u32,
    0xf407f3f4u32,
    0xea25cfeau32,
    0x65afca65u32,
    0x7a8ef47au32,
    0xaee947aeu32,
    0x08181008u32,
    0xbad56fbau32,
    0x7888f078u32,
    0x256f4a25u32,
    0x2e725c2eu32,
    0x1c24381cu32,
    0xa6f157a6u32,
    0xb4c773b4u32,
    0xc65197c6u32,
    0xe823cbe8u32,
    0xdd7ca1ddu32,
    0x749ce874u32,
    0x1f213e1fu32,
    0x4bdd964bu32,
    0xbddc61bdu32,
    0x8b860d8bu32,
    0x8a850f8au32,
    0x7090e070u32,
    0x3e427c3eu32,
    0xb5c471b5u32,
    0x66aacc66u32,
    0x48d89048u32,
    0x03050603u32,
    0xf601f7f6u32,
    0x0e121c0eu32,
    0x61a3c261u32,
    0x355f6a35u32,
    0x57f9ae57u32,
    0xb9d069b9u32,
    0x86911786u32,
    0xc15899c1u32,
    0x1d273a1du32,
    0x9eb9279eu32,
    0xe138d9e1u32,
    0xf813ebf8u32,
    0x98b32b98u32,
    0x11332211u32,
    0x69bbd269u32,
    0xd970a9d9u32,
    0x8e89078eu32,
    0x94a73394u32,
    0x9bb62d9bu32,
    0x1e223c1eu32,
    0x87921587u32,
    0xe920c9e9u32,
    0xce4987ceu32,
    0x55ffaa55u32,
    0x28785028u32,
    0xdf7aa5dfu32,
    0x8c8f038cu32,
    0xa1f859a1u32,
    0x89800989u32,
    0x0d171a0du32,
    0xbfda65bfu32,
    0xe631d7e6u32,
    0x42c68442u32,
    0x68b8d068u32,
    0x41c38241u32,
    0x99b02999u32,
    0x2d775a2du32,
    0x0f111e0fu32,
    0xb0cb7bb0u32,
    0x54fca854u32,
    0xbbd66dbbu32,
    0x163a2c16u32,
];

static TE3: [u32; 256] = [
    0x6363a5c6u32,
    0x7c7c84f8u32,
    0x777799eeu32,
    0x7b7b8df6u32,
    0xf2f20dffu32,
    0x6b6bbdd6u32,
    0x6f6fb1deu32,
    0xc5c55491u32,
    0x30305060u32,
    0x01010302u32,
    0x6767a9ceu32,
    0x2b2b7d56u32,
    0xfefe19e7u32,
    0xd7d762b5u32,
    0xababe64du32,
    0x76769aecu32,
    0xcaca458fu32,
    0x82829d1fu32,
    0xc9c94089u32,
    0x7d7d87fau32,
    0xfafa15efu32,
    0x5959ebb2u32,
    0x4747c98eu32,
    0xf0f00bfbu32,
    0xadadec41u32,
    0xd4d467b3u32,
    0xa2a2fd5fu32,
    0xafafea45u32,
    0x9c9cbf23u32,
    0xa4a4f753u32,
    0x727296e4u32,
    0xc0c05b9bu32,
    0xb7b7c275u32,
    0xfdfd1ce1u32,
    0x9393ae3du32,
    0x26266a4cu32,
    0x36365a6cu32,
    0x3f3f417eu32,
    0xf7f702f5u32,
    0xcccc4f83u32,
    0x34345c68u32,
    0xa5a5f451u32,
    0xe5e534d1u32,
    0xf1f108f9u32,
    0x717193e2u32,
    0xd8d873abu32,
    0x31315362u32,
    0x15153f2au32,
    0x04040c08u32,
    0xc7c75295u32,
    0x23236546u32,
    0xc3c35e9du32,
    0x18182830u32,
    0x9696a137u32,
    0x05050f0au32,
    0x9a9ab52fu32,
    0x0707090eu32,
    0x12123624u32,
    0x80809b1bu32,
    0xe2e23ddfu32,
    0xebeb26cdu32,
    0x2727694eu32,
    0xb2b2cd7fu32,
    0x75759feau32,
    0x09091b12u32,
    0x83839e1du32,
    0x2c2c7458u32,
    0x1a1a2e34u32,
    0x1b1b2d36u32,
    0x6e6eb2dcu32,
    0x5a5aeeb4u32,
    0xa0a0fb5bu32,
    0x5252f6a4u32,
    0x3b3b4d76u32,
    0xd6d661b7u32,
    0xb3b3ce7du32,
    0x29297b52u32,
    0xe3e33eddu32,
    0x2f2f715eu32,
    0x84849713u32,
    0x5353f5a6u32,
    0xd1d168b9u32,
    0x00000000u32,
    0xeded2cc1u32,
    0x20206040u32,
    0xfcfc1fe3u32,
    0xb1b1c879u32,
    0x5b5bedb6u32,
    0x6a6abed4u32,
    0xcbcb468du32,
    0xbebed967u32,
    0x39394b72u32,
    0x4a4ade94u32,
    0x4c4cd498u32,
    0x5858e8b0u32,
    0xcfcf4a85u32,
    0xd0d06bbbu32,
    0xefef2ac5u32,
    0xaaaae54fu32,
    0xfbfb16edu32,
    0x4343c586u32,
    0x4d4dd79au32,
    0x33335566u32,
    0x85859411u32,
    0x4545cf8au32,
    0xf9f910e9u32,
    0x02020604u32,
    0x7f7f81feu32,
    0x5050f0a0u32,
    0x3c3c4478u32,
    0x9f9fba25u32,
    0xa8a8e34bu32,
    0x5151f3a2u32,
    0xa3a3fe5du32,
    0x4040c080u32,
    0x8f8f8a05u32,
    0x9292ad3fu32,
    0x9d9dbc21u32,
    0x38384870u32,
    0xf5f504f1u32,
    0xbcbcdf63u32,
    0xb6b6c177u32,
    0xdada75afu32,
    0x21216342u32,
    0x10103020u32,
    0xffff1ae5u32,
    0xf3f30efdu32,
    0xd2d26dbfu32,
    0xcdcd4c81u32,
    0x0c0c1418u32,
    0x13133526u32,
    0xecec2fc3u32,
    0x5f5fe1beu32,
    0x9797a235u32,
    0x4444cc88u32,
    0x1717392eu32,
    0xc4c45793u32,
    0xa7a7f255u32,
    0x7e7e82fcu32,
    0x3d3d477au32,
    0x6464acc8u32,
    0x5d5de7bau32,
    0x19192b32u32,
    0x737395e6u32,
    0x6060a0c0u32,
    0x81819819u32,
    0x4f4fd19eu32,
    0xdcdc7fa3u32,
    0x22226644u32,
    0x2a2a7e54u32,
    0x9090ab3bu32,
    0x8888830bu32,
    0x4646ca8cu32,
    0xeeee29c7u32,
    0xb8b8d36bu32,
    0x14143c28u32,
    0xdede79a7u32,
    0x5e5ee2bcu32,
    0x0b0b1d16u32,
    0xdbdb76adu32,
    0xe0e03bdbu32,
    0x32325664u32,
    0x3a3a4e74u32,
    0x0a0a1e14u32,
    0x4949db92u32,
    0x06060a0cu32,
    0x24246c48u32,
    0x5c5ce4b8u32,
    0xc2c25d9fu32,
    0xd3d36ebdu32,
    0xacacef43u32,
    0x6262a6c4u32,
    0x9191a839u32,
    0x9595a431u32,
    0xe4e437d3u32,
    0x79798bf2u32,
    0xe7e732d5u32,
    0xc8c8438bu32,
    0x3737596eu32,
    0x6d6db7dau32,
    0x8d8d8c01u32,
    0xd5d564b1u32,
    0x4e4ed29cu32,
    0xa9a9e049u32,
    0x6c6cb4d8u32,
    0x5656faacu32,
    0xf4f407f3u32,
    0xeaea25cfu32,
    0x6565afcau32,
    0x7a7a8ef4u32,
    0xaeaee947u32,
    0x08081810u32,
    0xbabad56fu32,
    0x787888f0u32,
    0x25256f4au32,
    0x2e2e725cu32,
    0x1c1c2438u32,
    0xa6a6f157u32,
    0xb4b4c773u32,
    0xc6c65197u32,
    0xe8e823cbu32,
    0xdddd7ca1u32,
    0x74749ce8u32,
    0x1f1f213eu32,
    0x4b4bdd96u32,
    0xbdbddc61u32,
    0x8b8b860du32,
    0x8a8a850fu32,
    0x707090e0u32,
    0x3e3e427cu32,
    0xb5b5c471u32,
    0x6666aaccu32,
    0x4848d890u32,
    0x03030506u32,
    0xf6f601f7u32,
    0x0e0e121cu32,
    0x6161a3c2u32,
    0x35355f6au32,
    0x5757f9aeu32,
    0xb9b9d069u32,
    0x86869117u32,
    0xc1c15899u32,
    0x1d1d273au32,
    0x9e9eb927u32,
    0xe1e138d9u32,
    0xf8f813ebu32,
    0x9898b32bu32,
    0x11113322u32,
    0x6969bbd2u32,
    0xd9d970a9u32,
    0x8e8e8907u32,
    0x9494a733u32,
    0x9b9bb62du32,
    0x1e1e223cu32,
    0x87879215u32,
    0xe9e920c9u32,
    0xcece4987u32,
    0x5555ffaau32,
    0x28287850u32,
    0xdfdf7aa5u32,
    0x8c8c8f03u32,
    0xa1a1f859u32,
    0x89898009u32,
    0x0d0d171au32,
    0xbfbfda65u32,
    0xe6e631d7u32,
    0x4242c684u32,
    0x6868b8d0u32,
    0x4141c382u32,
    0x9999b029u32,
    0x2d2d775au32,
    0x0f0f111eu32,
    0xb0b0cb7bu32,
    0x5454fca8u32,
    0xbbbbd66du32,
    0x16163a2cu32,
];

static TE4: [u32; 256] = [
    0x63636363u32,
    0x7c7c7c7cu32,
    0x77777777u32,
    0x7b7b7b7bu32,
    0xf2f2f2f2u32,
    0x6b6b6b6bu32,
    0x6f6f6f6fu32,
    0xc5c5c5c5u32,
    0x30303030u32,
    0x01010101u32,
    0x67676767u32,
    0x2b2b2b2bu32,
    0xfefefefeu32,
    0xd7d7d7d7u32,
    0xababababu32,
    0x76767676u32,
    0xcacacacau32,
    0x82828282u32,
    0xc9c9c9c9u32,
    0x7d7d7d7du32,
    0xfafafafau32,
    0x59595959u32,
    0x47474747u32,
    0xf0f0f0f0u32,
    0xadadadadu32,
    0xd4d4d4d4u32,
    0xa2a2a2a2u32,
    0xafafafafu32,
    0x9c9c9c9cu32,
    0xa4a4a4a4u32,
    0x72727272u32,
    0xc0c0c0c0u32,
    0xb7b7b7b7u32,
    0xfdfdfdfdu32,
    0x93939393u32,
    0x26262626u32,
    0x36363636u32,
    0x3f3f3f3fu32,
    0xf7f7f7f7u32,
    0xccccccccu32,
    0x34343434u32,
    0xa5a5a5a5u32,
    0xe5e5e5e5u32,
    0xf1f1f1f1u32,
    0x71717171u32,
    0xd8d8d8d8u32,
    0x31313131u32,
    0x15151515u32,
    0x04040404u32,
    0xc7c7c7c7u32,
    0x23232323u32,
    0xc3c3c3c3u32,
    0x18181818u32,
    0x96969696u32,
    0x05050505u32,
    0x9a9a9a9au32,
    0x07070707u32,
    0x12121212u32,
    0x80808080u32,
    0xe2e2e2e2u32,
    0xebebebebu32,
    0x27272727u32,
    0xb2b2b2b2u32,
    0x75757575u32,
    0x09090909u32,
    0x83838383u32,
    0x2c2c2c2cu32,
    0x1a1a1a1au32,
    0x1b1b1b1bu32,
    0x6e6e6e6eu32,
    0x5a5a5a5au32,
    0xa0a0a0a0u32,
    0x52525252u32,
    0x3b3b3b3bu32,
    0xd6d6d6d6u32,
    0xb3b3b3b3u32,
    0x29292929u32,
    0xe3e3e3e3u32,
    0x2f2f2f2fu32,
    0x84848484u32,
    0x53535353u32,
    0xd1d1d1d1u32,
    0x00000000u32,
    0xededededu32,
    0x20202020u32,
    0xfcfcfcfcu32,
    0xb1b1b1b1u32,
    0x5b5b5b5bu32,
    0x6a6a6a6au32,
    0xcbcbcbcbu32,
    0xbebebebeu32,
    0x39393939u32,
    0x4a4a4a4au32,
    0x4c4c4c4cu32,
    0x58585858u32,
    0xcfcfcfcfu32,
    0xd0d0d0d0u32,
    0xefefefefu32,
    0xaaaaaaaau32,
    0xfbfbfbfbu32,
    0x43434343u32,
    0x4d4d4d4du32,
    0x33333333u32,
    0x85858585u32,
    0x45454545u32,
    0xf9f9f9f9u32,
    0x02020202u32,
    0x7f7f7f7fu32,
    0x50505050u32,
    0x3c3c3c3cu32,
    0x9f9f9f9fu32,
    0xa8a8a8a8u32,
    0x51515151u32,
    0xa3a3a3a3u32,
    0x40404040u32,
    0x8f8f8f8fu32,
    0x92929292u32,
    0x9d9d9d9du32,
    0x38383838u32,
    0xf5f5f5f5u32,
    0xbcbcbcbcu32,
    0xb6b6b6b6u32,
    0xdadadadau32,
    0x21212121u32,
    0x10101010u32,
    0xffffffffu32,
    0xf3f3f3f3u32,
    0xd2d2d2d2u32,
    0xcdcdcdcdu32,
    0x0c0c0c0cu32,
    0x13131313u32,
    0xececececu32,
    0x5f5f5f5fu32,
    0x97979797u32,
    0x44444444u32,
    0x17171717u32,
    0xc4c4c4c4u32,
    0xa7a7a7a7u32,
    0x7e7e7e7eu32,
    0x3d3d3d3du32,
    0x64646464u32,
    0x5d5d5d5du32,
    0x19191919u32,
    0x73737373u32,
    0x60606060u32,
    0x81818181u32,
    0x4f4f4f4fu32,
    0xdcdcdcdcu32,
    0x22222222u32,
    0x2a2a2a2au32,
    0x90909090u32,
    0x88888888u32,
    0x46464646u32,
    0xeeeeeeeeu32,
    0xb8b8b8b8u32,
    0x14141414u32,
    0xdedededeu32,
    0x5e5e5e5eu32,
    0x0b0b0b0bu32,
    0xdbdbdbdbu32,
    0xe0e0e0e0u32,
    0x32323232u32,
    0x3a3a3a3au32,
    0x0a0a0a0au32,
    0x49494949u32,
    0x06060606u32,
    0x24242424u32,
    0x5c5c5c5cu32,
    0xc2c2c2c2u32,
    0xd3d3d3d3u32,
    0xacacacacu32,
    0x62626262u32,
    0x91919191u32,
    0x95959595u32,
    0xe4e4e4e4u32,
    0x79797979u32,
    0xe7e7e7e7u32,
    0xc8c8c8c8u32,
    0x37373737u32,
    0x6d6d6d6du32,
    0x8d8d8d8du32,
    0xd5d5d5d5u32,
    0x4e4e4e4eu32,
    0xa9a9a9a9u32,
    0x6c6c6c6cu32,
    0x56565656u32,
    0xf4f4f4f4u32,
    0xeaeaeaeau32,
    0x65656565u32,
    0x7a7a7a7au32,
    0xaeaeaeaeu32,
    0x08080808u32,
    0xbabababau32,
    0x78787878u32,
    0x25252525u32,
    0x2e2e2e2eu32,
    0x1c1c1c1cu32,
    0xa6a6a6a6u32,
    0xb4b4b4b4u32,
    0xc6c6c6c6u32,
    0xe8e8e8e8u32,
    0xddddddddu32,
    0x74747474u32,
    0x1f1f1f1fu32,
    0x4b4b4b4bu32,
    0xbdbdbdbdu32,
    0x8b8b8b8bu32,
    0x8a8a8a8au32,
    0x70707070u32,
    0x3e3e3e3eu32,
    0xb5b5b5b5u32,
    0x66666666u32,
    0x48484848u32,
    0x03030303u32,
    0xf6f6f6f6u32,
    0x0e0e0e0eu32,
    0x61616161u32,
    0x35353535u32,
    0x57575757u32,
    0xb9b9b9b9u32,
    0x86868686u32,
    0xc1c1c1c1u32,
    0x1d1d1d1du32,
    0x9e9e9e9eu32,
    0xe1e1e1e1u32,
    0xf8f8f8f8u32,
    0x98989898u32,
    0x11111111u32,
    0x69696969u32,
    0xd9d9d9d9u32,
    0x8e8e8e8eu32,
    0x94949494u32,
    0x9b9b9b9bu32,
    0x1e1e1e1eu32,
    0x87878787u32,
    0xe9e9e9e9u32,
    0xcecececeu32,
    0x55555555u32,
    0x28282828u32,
    0xdfdfdfdfu32,
    0x8c8c8c8cu32,
    0xa1a1a1a1u32,
    0x89898989u32,
    0x0d0d0d0du32,
    0xbfbfbfbfu32,
    0xe6e6e6e6u32,
    0x42424242u32,
    0x68686868u32,
    0x41414141u32,
    0x99999999u32,
    0x2d2d2d2du32,
    0x0f0f0f0fu32,
    0xb0b0b0b0u32,
    0x54545454u32,
    0xbbbbbbbbu32,
    0x16161616u32,
];

static TD0: [u32; 256] = [
    0x51f4a750u32,
    0x7e416553u32,
    0x1a17a4c3u32,
    0x3a275e96u32,
    0x3bab6bcbu32,
    0x1f9d45f1u32,
    0xacfa58abu32,
    0x4be30393u32,
    0x2030fa55u32,
    0xad766df6u32,
    0x88cc7691u32,
    0xf5024c25u32,
    0x4fe5d7fcu32,
    0xc52acbd7u32,
    0x26354480u32,
    0xb562a38fu32,
    0xdeb15a49u32,
    0x25ba1b67u32,
    0x45ea0e98u32,
    0x5dfec0e1u32,
    0xc32f7502u32,
    0x814cf012u32,
    0x8d4697a3u32,
    0x6bd3f9c6u32,
    0x038f5fe7u32,
    0x15929c95u32,
    0xbf6d7aebu32,
    0x955259dau32,
    0xd4be832du32,
    0x587421d3u32,
    0x49e06929u32,
    0x8ec9c844u32,
    0x75c2896au32,
    0xf48e7978u32,
    0x99583e6bu32,
    0x27b971ddu32,
    0xbee14fb6u32,
    0xf088ad17u32,
    0xc920ac66u32,
    0x7dce3ab4u32,
    0x63df4a18u32,
    0xe51a3182u32,
    0x97513360u32,
    0x62537f45u32,
    0xb16477e0u32,
    0xbb6bae84u32,
    0xfe81a01cu32,
    0xf9082b94u32,
    0x70486858u32,
    0x8f45fd19u32,
    0x94de6c87u32,
    0x527bf8b7u32,
    0xab73d323u32,
    0x724b02e2u32,
    0xe31f8f57u32,
    0x6655ab2au32,
    0xb2eb2807u32,
    0x2fb5c203u32,
    0x86c57b9au32,
    0xd33708a5u32,
    0x302887f2u32,
    0x23bfa5b2u32,
    0x02036abau32,
    0xed16825cu32,
    0x8acf1c2bu32,
    0xa779b492u32,
    0xf307f2f0u32,
    0x4e69e2a1u32,
    0x65daf4cdu32,
    0x0605bed5u32,
    0xd134621fu32,
    0xc4a6fe8au32,
    0x342e539du32,
    0xa2f355a0u32,
    0x058ae132u32,
    0xa4f6eb75u32,
    0x0b83ec39u32,
    0x4060efaau32,
    0x5e719f06u32,
    0xbd6e1051u32,
    0x3e218af9u32,
    0x96dd063du32,
    0xdd3e05aeu32,
    0x4de6bd46u32,
    0x91548db5u32,
    0x71c45d05u32,
    0x0406d46fu32,
    0x605015ffu32,
    0x1998fb24u32,
    0xd6bde997u32,
    0x894043ccu32,
    0x67d99e77u32,
    0xb0e842bdu32,
    0x07898b88u32,
    0xe7195b38u32,
    0x79c8eedbu32,
    0xa17c0a47u32,
    0x7c420fe9u32,
    0xf8841ec9u32,
    0x00000000u32,
    0x09808683u32,
    0x322bed48u32,
    0x1e1170acu32,
    0x6c5a724eu32,
    0xfd0efffbu32,
    0x0f853856u32,
    0x3daed51eu32,
    0x362d3927u32,
    0x0a0fd964u32,
    0x685ca621u32,
    0x9b5b54d1u32,
    0x24362e3au32,
    0x0c0a67b1u32,
    0x9357e70fu32,
    0xb4ee96d2u32,
    0x1b9b919eu32,
    0x80c0c54fu32,
    0x61dc20a2u32,
    0x5a774b69u32,
    0x1c121a16u32,
    0xe293ba0au32,
    0xc0a02ae5u32,
    0x3c22e043u32,
    0x121b171du32,
    0x0e090d0bu32,
    0xf28bc7adu32,
    0x2db6a8b9u32,
    0x141ea9c8u32,
    0x57f11985u32,
    0xaf75074cu32,
    0xee99ddbbu32,
    0xa37f60fdu32,
    0xf701269fu32,
    0x5c72f5bcu32,
    0x44663bc5u32,
    0x5bfb7e34u32,
    0x8b432976u32,
    0xcb23c6dcu32,
    0xb6edfc68u32,
    0xb8e4f163u32,
    0xd731dccau32,
    0x42638510u32,
    0x13972240u32,
    0x84c61120u32,
    0x854a247du32,
    0xd2bb3df8u32,
    0xaef93211u32,
    0xc729a16du32,
    0x1d9e2f4bu32,
    0xdcb230f3u32,
    0x0d8652ecu32,
    0x77c1e3d0u32,
    0x2bb3166cu32,
    0xa970b999u32,
    0x119448fau32,
    0x47e96422u32,
    0xa8fc8cc4u32,
    0xa0f03f1au32,
    0x567d2cd8u32,
    0x223390efu32,
    0x87494ec7u32,
    0xd938d1c1u32,
    0x8ccaa2feu32,
    0x98d40b36u32,
    0xa6f581cfu32,
    0xa57ade28u32,
    0xdab78e26u32,
    0x3fadbfa4u32,
    0x2c3a9de4u32,
    0x5078920du32,
    0x6a5fcc9bu32,
    0x547e4662u32,
    0xf68d13c2u32,
    0x90d8b8e8u32,
    0x2e39f75eu32,
    0x82c3aff5u32,
    0x9f5d80beu32,
    0x69d0937cu32,
    0x6fd52da9u32,
    0xcf2512b3u32,
    0xc8ac993bu32,
    0x10187da7u32,
    0xe89c636eu32,
    0xdb3bbb7bu32,
    0xcd267809u32,
    0x6e5918f4u32,
    0xec9ab701u32,
    0x834f9aa8u32,
    0xe6956e65u32,
    0xaaffe67eu32,
    0x21bccf08u32,
    0xef15e8e6u32,
    0xbae79bd9u32,
    0x4a6f36ceu32,
    0xea9f09d4u32,
    0x29b07cd6u32,
    0x31a4b2afu32,
    0x2a3f2331u32,
    0xc6a59430u32,
    0x35a266c0u32,
    0x744ebc37u32,
    0xfc82caa6u32,
    0xe090d0b0u32,
    0x33a7d815u32,
    0xf104984au32,
    0x41ecdaf7u32,
    0x7fcd500eu32,
    0x1791f62fu32,
    0x764dd68du32,
    0x43efb04du32,
    0xccaa4d54u32,
    0xe49604dfu32,
    0x9ed1b5e3u32,
    0x4c6a881bu32,
    0xc12c1fb8u32,
    0x4665517fu32,
    0x9d5eea04u32,
    0x018c355du32,
    0xfa877473u32,
    0xfb0b412eu32,
    0xb3671d5au32,
    0x92dbd252u32,
    0xe9105633u32,
    0x6dd64713u32,
    0x9ad7618cu32,
    0x37a10c7au32,
    0x59f8148eu32,
    0xeb133c89u32,
    0xcea927eeu32,
    0xb761c935u32,
    0xe11ce5edu32,
    0x7a47b13cu32,
    0x9cd2df59u32,
    0x55f2733fu32,
    0x1814ce79u32,
    0x73c737bfu32,
    0x53f7cdeau32,
    0x5ffdaa5bu32,
    0xdf3d6f14u32,
    0x7844db86u32,
    0xcaaff381u32,
    0xb968c43eu32,
    0x3824342cu32,
    0xc2a3405fu32,
    0x161dc372u32,
    0xbce2250cu32,
    0x283c498bu32,
    0xff0d9541u32,
    0x39a80171u32,
    0x080cb3deu32,
    0xd8b4e49cu32,
    0x6456c190u32,
    0x7bcb8461u32,
    0xd532b670u32,
    0x486c5c74u32,
    0xd0b85742u32,
];

static TD1: [u32; 256] = [
    0x5051f4a7u32,
    0x537e4165u32,
    0xc31a17a4u32,
    0x963a275eu32,
    0xcb3bab6bu32,
    0xf11f9d45u32,
    0xabacfa58u32,
    0x934be303u32,
    0x552030fau32,
    0xf6ad766du32,
    0x9188cc76u32,
    0x25f5024cu32,
    0xfc4fe5d7u32,
    0xd7c52acbu32,
    0x80263544u32,
    0x8fb562a3u32,
    0x49deb15au32,
    0x6725ba1bu32,
    0x9845ea0eu32,
    0xe15dfec0u32,
    0x02c32f75u32,
    0x12814cf0u32,
    0xa38d4697u32,
    0xc66bd3f9u32,
    0xe7038f5fu32,
    0x9515929cu32,
    0xebbf6d7au32,
    0xda955259u32,
    0x2dd4be83u32,
    0xd3587421u32,
    0x2949e069u32,
    0x448ec9c8u32,
    0x6a75c289u32,
    0x78f48e79u32,
    0x6b99583eu32,
    0xdd27b971u32,
    0xb6bee14fu32,
    0x17f088adu32,
    0x66c920acu32,
    0xb47dce3au32,
    0x1863df4au32,
    0x82e51a31u32,
    0x60975133u32,
    0x4562537fu32,
    0xe0b16477u32,
    0x84bb6baeu32,
    0x1cfe81a0u32,
    0x94f9082bu32,
    0x58704868u32,
    0x198f45fdu32,
    0x8794de6cu32,
    0xb7527bf8u32,
    0x23ab73d3u32,
    0xe2724b02u32,
    0x57e31f8fu32,
    0x2a6655abu32,
    0x07b2eb28u32,
    0x032fb5c2u32,
    0x9a86c57bu32,
    0xa5d33708u32,
    0xf2302887u32,
    0xb223bfa5u32,
    0xba02036au32,
    0x5ced1682u32,
    0x2b8acf1cu32,
    0x92a779b4u32,
    0xf0f307f2u32,
    0xa14e69e2u32,
    0xcd65daf4u32,
    0xd50605beu32,
    0x1fd13462u32,
    0x8ac4a6feu32,
    0x9d342e53u32,
    0xa0a2f355u32,
    0x32058ae1u32,
    0x75a4f6ebu32,
    0x390b83ecu32,
    0xaa4060efu32,
    0x065e719fu32,
    0x51bd6e10u32,
    0xf93e218au32,
    0x3d96dd06u32,
    0xaedd3e05u32,
    0x464de6bdu32,
    0xb591548du32,
    0x0571c45du32,
    0x6f0406d4u32,
    0xff605015u32,
    0x241998fbu32,
    0x97d6bde9u32,
    0xcc894043u32,
    0x7767d99eu32,
    0xbdb0e842u32,
    0x8807898bu32,
    0x38e7195bu32,
    0xdb79c8eeu32,
    0x47a17c0au32,
    0xe97c420fu32,
    0xc9f8841eu32,
    0x00000000u32,
    0x83098086u32,
    0x48322bedu32,
    0xac1e1170u32,
    0x4e6c5a72u32,
    0xfbfd0effu32,
    0x560f8538u32,
    0x1e3daed5u32,
    0x27362d39u32,
    0x640a0fd9u32,
    0x21685ca6u32,
    0xd19b5b54u32,
    0x3a24362eu32,
    0xb10c0a67u32,
    0x0f9357e7u32,
    0xd2b4ee96u32,
    0x9e1b9b91u32,
    0x4f80c0c5u32,
    0xa261dc20u32,
    0x695a774bu32,
    0x161c121au32,
    0x0ae293bau32,
    0xe5c0a02au32,
    0x433c22e0u32,
    0x1d121b17u32,
    0x0b0e090du32,
    0xadf28bc7u32,
    0xb92db6a8u32,
    0xc8141ea9u32,
    0x8557f119u32,
    0x4caf7507u32,
    0xbbee99ddu32,
    0xfda37f60u32,
    0x9ff70126u32,
    0xbc5c72f5u32,
    0xc544663bu32,
    0x345bfb7eu32,
    0x768b4329u32,
    0xdccb23c6u32,
    0x68b6edfcu32,
    0x63b8e4f1u32,
    0xcad731dcu32,
    0x10426385u32,
    0x40139722u32,
    0x2084c611u32,
    0x7d854a24u32,
    0xf8d2bb3du32,
    0x11aef932u32,
    0x6dc729a1u32,
    0x4b1d9e2fu32,
    0xf3dcb230u32,
    0xec0d8652u32,
    0xd077c1e3u32,
    0x6c2bb316u32,
    0x99a970b9u32,
    0xfa119448u32,
    0x2247e964u32,
    0xc4a8fc8cu32,
    0x1aa0f03fu32,
    0xd8567d2cu32,
    0xef223390u32,
    0xc787494eu32,
    0xc1d938d1u32,
    0xfe8ccaa2u32,
    0x3698d40bu32,
    0xcfa6f581u32,
    0x28a57adeu32,
    0x26dab78eu32,
    0xa43fadbfu32,
    0xe42c3a9du32,
    0x0d507892u32,
    0x9b6a5fccu32,
    0x62547e46u32,
    0xc2f68d13u32,
    0xe890d8b8u32,
    0x5e2e39f7u32,
    0xf582c3afu32,
    0xbe9f5d80u32,
    0x7c69d093u32,
    0xa96fd52du32,
    0xb3cf2512u32,
    0x3bc8ac99u32,
    0xa710187du32,
    0x6ee89c63u32,
    0x7bdb3bbbu32,
    0x09cd2678u32,
    0xf46e5918u32,
    0x01ec9ab7u32,
    0xa8834f9au32,
    0x65e6956eu32,
    0x7eaaffe6u32,
    0x0821bccfu32,
    0xe6ef15e8u32,
    0xd9bae79bu32,
    0xce4a6f36u32,
    0xd4ea9f09u32,
    0xd629b07cu32,
    0xaf31a4b2u32,
    0x312a3f23u32,
    0x30c6a594u32,
    0xc035a266u32,
    0x37744ebcu32,
    0xa6fc82cau32,
    0xb0e090d0u32,
    0x1533a7d8u32,
    0x4af10498u32,
    0xf741ecdau32,
    0x0e7fcd50u32,
    0x2f1791f6u32,
    0x8d764dd6u32,
    0x4d43efb0u32,
    0x54ccaa4du32,
    0xdfe49604u32,
    0xe39ed1b5u32,
    0x1b4c6a88u32,
    0xb8c12c1fu32,
    0x7f466551u32,
    0x049d5eeau32,
    0x5d018c35u32,
    0x73fa8774u32,
    0x2efb0b41u32,
    0x5ab3671du32,
    0x5292dbd2u32,
    0x33e91056u32,
    0x136dd647u32,
    0x8c9ad761u32,
    0x7a37a10cu32,
    0x8e59f814u32,
    0x89eb133cu32,
    0xeecea927u32,
    0x35b761c9u32,
    0xede11ce5u32,
    0x3c7a47b1u32,
    0x599cd2dfu32,
    0x3f55f273u32,
    0x791814ceu32,
    0xbf73c737u32,
    0xea53f7cdu32,
    0x5b5ffdaau32,
    0x14df3d6fu32,
    0x867844dbu32,
    0x81caaff3u32,
    0x3eb968c4u32,
    0x2c382434u32,
    0x5fc2a340u32,
    0x72161dc3u32,
    0x0cbce225u32,
    0x8b283c49u32,
    0x41ff0d95u32,
    0x7139a801u32,
    0xde080cb3u32,
    0x9cd8b4e4u32,
    0x906456c1u32,
    0x617bcb84u32,
    0x70d532b6u32,
    0x74486c5cu32,
    0x42d0b857u32,
];

static TD2: [u32; 256] = [
    0xa75051f4u32,
    0x65537e41u32,
    0xa4c31a17u32,
    0x5e963a27u32,
    0x6bcb3babu32,
    0x45f11f9du32,
    0x58abacfau32,
    0x03934be3u32,
    0xfa552030u32,
    0x6df6ad76u32,
    0x769188ccu32,
    0x4c25f502u32,
    0xd7fc4fe5u32,
    0xcbd7c52au32,
    0x44802635u32,
    0xa38fb562u32,
    0x5a49deb1u32,
    0x1b6725bau32,
    0x0e9845eau32,
    0xc0e15dfeu32,
    0x7502c32fu32,
    0xf012814cu32,
    0x97a38d46u32,
    0xf9c66bd3u32,
    0x5fe7038fu32,
    0x9c951592u32,
    0x7aebbf6du32,
    0x59da9552u32,
    0x832dd4beu32,
    0x21d35874u32,
    0x692949e0u32,
    0xc8448ec9u32,
    0x896a75c2u32,
    0x7978f48eu32,
    0x3e6b9958u32,
    0x71dd27b9u32,
    0x4fb6bee1u32,
    0xad17f088u32,
    0xac66c920u32,
    0x3ab47dceu32,
    0x4a1863dfu32,
    0x3182e51au32,
    0x33609751u32,
    0x7f456253u32,
    0x77e0b164u32,
    0xae84bb6bu32,
    0xa01cfe81u32,
    0x2b94f908u32,
    0x68587048u32,
    0xfd198f45u32,
    0x6c8794deu32,
    0xf8b7527bu32,
    0xd323ab73u32,
    0x02e2724bu32,
    0x8f57e31fu32,
    0xab2a6655u32,
    0x2807b2ebu32,
    0xc2032fb5u32,
    0x7b9a86c5u32,
    0x08a5d337u32,
    0x87f23028u32,
    0xa5b223bfu32,
    0x6aba0203u32,
    0x825ced16u32,
    0x1c2b8acfu32,
    0xb492a779u32,
    0xf2f0f307u32,
    0xe2a14e69u32,
    0xf4cd65dau32,
    0xbed50605u32,
    0x621fd134u32,
    0xfe8ac4a6u32,
    0x539d342eu32,
    0x55a0a2f3u32,
    0xe132058au32,
    0xeb75a4f6u32,
    0xec390b83u32,
    0xefaa4060u32,
    0x9f065e71u32,
    0x1051bd6eu32,
    0x8af93e21u32,
    0x063d96ddu32,
    0x05aedd3eu32,
    0xbd464de6u32,
    0x8db59154u32,
    0x5d0571c4u32,
    0xd46f0406u32,
    0x15ff6050u32,
    0xfb241998u32,
    0xe997d6bdu32,
    0x43cc8940u32,
    0x9e7767d9u32,
    0x42bdb0e8u32,
    0x8b880789u32,
    0x5b38e719u32,
    0xeedb79c8u32,
    0x0a47a17cu32,
    0x0fe97c42u32,
    0x1ec9f884u32,
    0x00000000u32,
    0x86830980u32,
    0xed48322bu32,
    0x70ac1e11u32,
    0x724e6c5au32,
    0xfffbfd0eu32,
    0x38560f85u32,
    0xd51e3daeu32,
    0x3927362du32,
    0xd9640a0fu32,
    0xa621685cu32,
    0x54d19b5bu32,
    0x2e3a2436u32,
    0x67b10c0au32,
    0xe70f9357u32,
    0x96d2b4eeu32,
    0x919e1b9bu32,
    0xc54f80c0u32,
    0x20a261dcu32,
    0x4b695a77u32,
    0x1a161c12u32,
    0xba0ae293u32,
    0x2ae5c0a0u32,
    0xe0433c22u32,
    0x171d121bu32,
    0x0d0b0e09u32,
    0xc7adf28bu32,
    0xa8b92db6u32,
    0xa9c8141eu32,
    0x198557f1u32,
    0x074caf75u32,
    0xddbbee99u32,
    0x60fda37fu32,
    0x269ff701u32,
    0xf5bc5c72u32,
    0x3bc54466u32,
    0x7e345bfbu32,
    0x29768b43u32,
    0xc6dccb23u32,
    0xfc68b6edu32,
    0xf163b8e4u32,
    0xdccad731u32,
    0x85104263u32,
    0x22401397u32,
    0x112084c6u32,
    0x247d854au32,
    0x3df8d2bbu32,
    0x3211aef9u32,
    0xa16dc729u32,
    0x2f4b1d9eu32,
    0x30f3dcb2u32,
    0x52ec0d86u32,
    0xe3d077c1u32,
    0x166c2bb3u32,
    0xb999a970u32,
    0x48fa1194u32,
    0x642247e9u32,
    0x8cc4a8fcu32,
    0x3f1aa0f0u32,
    0x2cd8567du32,
    0x90ef2233u32,
    0x4ec78749u32,
    0xd1c1d938u32,
    0xa2fe8ccau32,
    0x0b3698d4u32,
    0x81cfa6f5u32,
    0xde28a57au32,
    0x8e26dab7u32,
    0xbfa43fadu32,
    0x9de42c3au32,
    0x920d5078u32,
    0xcc9b6a5fu32,
    0x4662547eu32,
    0x13c2f68du32,
    0xb8e890d8u32,
    0xf75e2e39u32,
    0xaff582c3u32,
    0x80be9f5du32,
    0x937c69d0u32,
    0x2da96fd5u32,
    0x12b3cf25u32,
    0x993bc8acu32,
    0x7da71018u32,
    0x636ee89cu32,
    0xbb7bdb3bu32,
    0x7809cd26u32,
    0x18f46e59u32,
    0xb701ec9au32,
    0x9aa8834fu32,
    0x6e65e695u32,
    0xe67eaaffu32,
    0xcf0821bcu32,
    0xe8e6ef15u32,
    0x9bd9bae7u32,
    0x36ce4a6fu32,
    0x09d4ea9fu32,
    0x7cd629b0u32,
    0xb2af31a4u32,
    0x23312a3fu32,
    0x9430c6a5u32,
    0x66c035a2u32,
    0xbc37744eu32,
    0xcaa6fc82u32,
    0xd0b0e090u32,
    0xd81533a7u32,
    0x984af104u32,
    0xdaf741ecu32,
    0x500e7fcdu32,
    0xf62f1791u32,
    0xd68d764du32,
    0xb04d43efu32,
    0x4d54ccaau32,
    0x04dfe496u32,
    0xb5e39ed1u32,
    0x881b4c6au32,
    0x1fb8c12cu32,
    0x517f4665u32,
    0xea049d5eu32,
    0x355d018cu32,
    0x7473fa87u32,
    0x412efb0bu32,
    0x1d5ab367u32,
    0xd25292dbu32,
    0x5633e910u32,
    0x47136dd6u32,
    0x618c9ad7u32,
    0x0c7a37a1u32,
    0x148e59f8u32,
    0x3c89eb13u32,
    0x27eecea9u32,
    0xc935b761u32,
    0xe5ede11cu32,
    0xb13c7a47u32,
    0xdf599cd2u32,
    0x733f55f2u32,
    0xce791814u32,
    0x37bf73c7u32,
    0xcdea53f7u32,
    0xaa5b5ffdu32,
    0x6f14df3du32,
    0xdb867844u32,
    0xf381caafu32,
    0xc43eb968u32,
    0x342c3824u32,
    0x405fc2a3u32,
    0xc372161du32,
    0x250cbce2u32,
    0x498b283cu32,
    0x9541ff0du32,
    0x017139a8u32,
    0xb3de080cu32,
    0xe49cd8b4u32,
    0xc1906456u32,
    0x84617bcbu32,
    0xb670d532u32,
    0x5c74486cu32,
    0x5742d0b8u32,
];

static TD3: [u32; 256] = [
    0xf4a75051u32,
    0x4165537eu32,
    0x17a4c31au32,
    0x275e963au32,
    0xab6bcb3bu32,
    0x9d45f11fu32,
    0xfa58abacu32,
    0xe303934bu32,
    0x30fa5520u32,
    0x766df6adu32,
    0xcc769188u32,
    0x024c25f5u32,
    0xe5d7fc4fu32,
    0x2acbd7c5u32,
    0x35448026u32,
    0x62a38fb5u32,
    0xb15a49deu32,
    0xba1b6725u32,
    0xea0e9845u32,
    0xfec0e15du32,
    0x2f7502c3u32,
    0x4cf01281u32,
    0x4697a38du32,
    0xd3f9c66bu32,
    0x8f5fe703u32,
    0x929c9515u32,
    0x6d7aebbfu32,
    0x5259da95u32,
    0xbe832dd4u32,
    0x7421d358u32,
    0xe0692949u32,
    0xc9c8448eu32,
    0xc2896a75u32,
    0x8e7978f4u32,
    0x583e6b99u32,
    0xb971dd27u32,
    0xe14fb6beu32,
    0x88ad17f0u32,
    0x20ac66c9u32,
    0xce3ab47du32,
    0xdf4a1863u32,
    0x1a3182e5u32,
    0x51336097u32,
    0x537f4562u32,
    0x6477e0b1u32,
    0x6bae84bbu32,
    0x81a01cfeu32,
    0x082b94f9u32,
    0x48685870u32,
    0x45fd198fu32,
    0xde6c8794u32,
    0x7bf8b752u32,
    0x73d323abu32,
    0x4b02e272u32,
    0x1f8f57e3u32,
    0x55ab2a66u32,
    0xeb2807b2u32,
    0xb5c2032fu32,
    0xc57b9a86u32,
    0x3708a5d3u32,
    0x2887f230u32,
    0xbfa5b223u32,
    0x036aba02u32,
    0x16825cedu32,
    0xcf1c2b8au32,
    0x79b492a7u32,
    0x07f2f0f3u32,
    0x69e2a14eu32,
    0xdaf4cd65u32,
    0x05bed506u32,
    0x34621fd1u32,
    0xa6fe8ac4u32,
    0x2e539d34u32,
    0xf355a0a2u32,
    0x8ae13205u32,
    0xf6eb75a4u32,
    0x83ec390bu32,
    0x60efaa40u32,
    0x719f065eu32,
    0x6e1051bdu32,
    0x218af93eu32,
    0xdd063d96u32,
    0x3e05aeddu32,
    0xe6bd464du32,
    0x548db591u32,
    0xc45d0571u32,
    0x06d46f04u32,
    0x5015ff60u32,
    0x98fb2419u32,
    0xbde997d6u32,
    0x4043cc89u32,
    0xd99e7767u32,
    0xe842bdb0u32,
    0x898b8807u32,
    0x195b38e7u32,
    0xc8eedb79u32,
    0x7c0a47a1u32,
    0x420fe97cu32,
    0x841ec9f8u32,
    0x00000000u32,
    0x80868309u32,
    0x2bed4832u32,
    0x1170ac1eu32,
    0x5a724e6cu32,
    0x0efffbfdu32,
    0x8538560fu32,
    0xaed51e3du32,
    0x2d392736u32,
    0x0fd9640au32,
    0x5ca62168u32,
    0x5b54d19bu32,
    0x362e3a24u32,
    0x0a67b10cu32,
    0x57e70f93u32,
    0xee96d2b4u32,
    0x9b919e1bu32,
    0xc0c54f80u32,
    0xdc20a261u32,
    0x774b695au32,
    0x121a161cu32,
    0x93ba0ae2u32,
    0xa02ae5c0u32,
    0x22e0433cu32,
    0x1b171d12u32,
    0x090d0b0eu32,
    0x8bc7adf2u32,
    0xb6a8b92du32,
    0x1ea9c814u32,
    0xf1198557u32,
    0x75074cafu32,
    0x99ddbbeeu32,
    0x7f60fda3u32,
    0x01269ff7u32,
    0x72f5bc5cu32,
    0x663bc544u32,
    0xfb7e345bu32,
    0x4329768bu32,
    0x23c6dccbu32,
    0xedfc68b6u32,
    0xe4f163b8u32,
    0x31dccad7u32,
    0x63851042u32,
    0x97224013u32,
    0xc6112084u32,
    0x4a247d85u32,
    0xbb3df8d2u32,
    0xf93211aeu32,
    0x29a16dc7u32,
    0x9e2f4b1du32,
    0xb230f3dcu32,
    0x8652ec0du32,
    0xc1e3d077u32,
    0xb3166c2bu32,
    0x70b999a9u32,
    0x9448fa11u32,
    0xe9642247u32,
    0xfc8cc4a8u32,
    0xf03f1aa0u32,
    0x7d2cd856u32,
    0x3390ef22u32,
    0x494ec787u32,
    0x38d1c1d9u32,
    0xcaa2fe8cu32,
    0xd40b3698u32,
    0xf581cfa6u32,
    0x7ade28a5u32,
    0xb78e26dau32,
    0xadbfa43fu32,
    0x3a9de42cu32,
    0x78920d50u32,
    0x5fcc9b6au32,
    0x7e466254u32,
    0x8d13c2f6u32,
    0xd8b8e890u32,
    0x39f75e2eu32,
    0xc3aff582u32,
    0x5d80be9fu32,
    0xd0937c69u32,
    0xd52da96fu32,
    0x2512b3cfu32,
    0xac993bc8u32,
    0x187da710u32,
    0x9c636ee8u32,
    0x3bbb7bdbu32,
    0x267809cdu32,
    0x5918f46eu32,
    0x9ab701ecu32,
    0x4f9aa883u32,
    0x956e65e6u32,
    0xffe67eaau32,
    0xbccf0821u32,
    0x15e8e6efu32,
    0xe79bd9bau32,
    0x6f36ce4au32,
    0x9f09d4eau32,
    0xb07cd629u32,
    0xa4b2af31u32,
    0x3f23312au32,
    0xa59430c6u32,
    0xa266c035u32,
    0x4ebc3774u32,
    0x82caa6fcu32,
    0x90d0b0e0u32,
    0xa7d81533u32,
    0x04984af1u32,
    0xecdaf741u32,
    0xcd500e7fu32,
    0x91f62f17u32,
    0x4dd68d76u32,
    0xefb04d43u32,
    0xaa4d54ccu32,
    0x9604dfe4u32,
    0xd1b5e39eu32,
    0x6a881b4cu32,
    0x2c1fb8c1u32,
    0x65517f46u32,
    0x5eea049du32,
    0x8c355d01u32,
    0x877473fau32,
    0x0b412efbu32,
    0x671d5ab3u32,
    0xdbd25292u32,
    0x105633e9u32,
    0xd647136du32,
    0xd7618c9au32,
    0xa10c7a37u32,
    0xf8148e59u32,
    0x133c89ebu32,
    0xa927eeceu32,
    0x61c935b7u32,
    0x1ce5ede1u32,
    0x47b13c7au32,
    0xd2df599cu32,
    0xf2733f55u32,
    0x14ce7918u32,
    0xc737bf73u32,
    0xf7cdea53u32,
    0xfdaa5b5fu32,
    0x3d6f14dfu32,
    0x44db8678u32,
    0xaff381cau32,
    0x68c43eb9u32,
    0x24342c38u32,
    0xa3405fc2u32,
    0x1dc37216u32,
    0xe2250cbcu32,
    0x3c498b28u32,
    0x0d9541ffu32,
    0xa8017139u32,
    0x0cb3de08u32,
    0xb4e49cd8u32,
    0x56c19064u32,
    0xcb84617bu32,
    0x32b670d5u32,
    0x6c5c7448u32,
    0xb85742d0u32,
];

static TD4: [u32; 256] = [
    0x52525252u32,
    0x09090909u32,
    0x6a6a6a6au32,
    0xd5d5d5d5u32,
    0x30303030u32,
    0x36363636u32,
    0xa5a5a5a5u32,
    0x38383838u32,
    0xbfbfbfbfu32,
    0x40404040u32,
    0xa3a3a3a3u32,
    0x9e9e9e9eu32,
    0x81818181u32,
    0xf3f3f3f3u32,
    0xd7d7d7d7u32,
    0xfbfbfbfbu32,
    0x7c7c7c7cu32,
    0xe3e3e3e3u32,
    0x39393939u32,
    0x82828282u32,
    0x9b9b9b9bu32,
    0x2f2f2f2fu32,
    0xffffffffu32,
    0x87878787u32,
    0x34343434u32,
    0x8e8e8e8eu32,
    0x43434343u32,
    0x44444444u32,
    0xc4c4c4c4u32,
    0xdedededeu32,
    0xe9e9e9e9u32,
    0xcbcbcbcbu32,
    0x54545454u32,
    0x7b7b7b7bu32,
    0x94949494u32,
    0x32323232u32,
    0xa6a6a6a6u32,
    0xc2c2c2c2u32,
    0x23232323u32,
    0x3d3d3d3du32,
    0xeeeeeeeeu32,
    0x4c4c4c4cu32,
    0x95959595u32,
    0x0b0b0b0bu32,
    0x42424242u32,
    0xfafafafau32,
    0xc3c3c3c3u32,
    0x4e4e4e4eu32,
    0x08080808u32,
    0x2e2e2e2eu32,
    0xa1a1a1a1u32,
    0x66666666u32,
    0x28282828u32,
    0xd9d9d9d9u32,
    0x24242424u32,
    0xb2b2b2b2u32,
    0x76767676u32,
    0x5b5b5b5bu32,
    0xa2a2a2a2u32,
    0x49494949u32,
    0x6d6d6d6du32,
    0x8b8b8b8bu32,
    0xd1d1d1d1u32,
    0x25252525u32,
    0x72727272u32,
    0xf8f8f8f8u32,
    0xf6f6f6f6u32,
    0x64646464u32,
    0x86868686u32,
    0x68686868u32,
    0x98989898u32,
    0x16161616u32,
    0xd4d4d4d4u32,
    0xa4a4a4a4u32,
    0x5c5c5c5cu32,
    0xccccccccu32,
    0x5d5d5d5du32,
    0x65656565u32,
    0xb6b6b6b6u32,
    0x92929292u32,
    0x6c6c6c6cu32,
    0x70707070u32,
    0x48484848u32,
    0x50505050u32,
    0xfdfdfdfdu32,
    0xededededu32,
    0xb9b9b9b9u32,
    0xdadadadau32,
    0x5e5e5e5eu32,
    0x15151515u32,
    0x46464646u32,
    0x57575757u32,
    0xa7a7a7a7u32,
    0x8d8d8d8du32,
    0x9d9d9d9du32,
    0x84848484u32,
    0x90909090u32,
    0xd8d8d8d8u32,
    0xababababu32,
    0x00000000u32,
    0x8c8c8c8cu32,
    0xbcbcbcbcu32,
    0xd3d3d3d3u32,
    0x0a0a0a0au32,
    0xf7f7f7f7u32,
    0xe4e4e4e4u32,
    0x58585858u32,
    0x05050505u32,
    0xb8b8b8b8u32,
    0xb3b3b3b3u32,
    0x45454545u32,
    0x06060606u32,
    0xd0d0d0d0u32,
    0x2c2c2c2cu32,
    0x1e1e1e1eu32,
    0x8f8f8f8fu32,
    0xcacacacau32,
    0x3f3f3f3fu32,
    0x0f0f0f0fu32,
    0x02020202u32,
    0xc1c1c1c1u32,
    0xafafafafu32,
    0xbdbdbdbdu32,
    0x03030303u32,
    0x01010101u32,
    0x13131313u32,
    0x8a8a8a8au32,
    0x6b6b6b6bu32,
    0x3a3a3a3au32,
    0x91919191u32,
    0x11111111u32,
    0x41414141u32,
    0x4f4f4f4fu32,
    0x67676767u32,
    0xdcdcdcdcu32,
    0xeaeaeaeau32,
    0x97979797u32,
    0xf2f2f2f2u32,
    0xcfcfcfcfu32,
    0xcecececeu32,
    0xf0f0f0f0u32,
    0xb4b4b4b4u32,
    0xe6e6e6e6u32,
    0x73737373u32,
    0x96969696u32,
    0xacacacacu32,
    0x74747474u32,
    0x22222222u32,
    0xe7e7e7e7u32,
    0xadadadadu32,
    0x35353535u32,
    0x85858585u32,
    0xe2e2e2e2u32,
    0xf9f9f9f9u32,
    0x37373737u32,
    0xe8e8e8e8u32,
    0x1c1c1c1cu32,
    0x75757575u32,
    0xdfdfdfdfu32,
    0x6e6e6e6eu32,
    0x47474747u32,
    0xf1f1f1f1u32,
    0x1a1a1a1au32,
    0x71717171u32,
    0x1d1d1d1du32,
    0x29292929u32,
    0xc5c5c5c5u32,
    0x89898989u32,
    0x6f6f6f6fu32,
    0xb7b7b7b7u32,
    0x62626262u32,
    0x0e0e0e0eu32,
    0xaaaaaaaau32,
    0x18181818u32,
    0xbebebebeu32,
    0x1b1b1b1bu32,
    0xfcfcfcfcu32,
    0x56565656u32,
    0x3e3e3e3eu32,
    0x4b4b4b4bu32,
    0xc6c6c6c6u32,
    0xd2d2d2d2u32,
    0x79797979u32,
    0x20202020u32,
    0x9a9a9a9au32,
    0xdbdbdbdbu32,
    0xc0c0c0c0u32,
    0xfefefefeu32,
    0x78787878u32,
    0xcdcdcdcdu32,
    0x5a5a5a5au32,
    0xf4f4f4f4u32,
    0x1f1f1f1fu32,
    0xddddddddu32,
    0xa8a8a8a8u32,
    0x33333333u32,
    0x88888888u32,
    0x07070707u32,
    0xc7c7c7c7u32,
    0x31313131u32,
    0xb1b1b1b1u32,
    0x12121212u32,
    0x10101010u32,
    0x59595959u32,
    0x27272727u32,
    0x80808080u32,
    0xececececu32,
    0x5f5f5f5fu32,
    0x60606060u32,
    0x51515151u32,
    0x7f7f7f7fu32,
    0xa9a9a9a9u32,
    0x19191919u32,
    0xb5b5b5b5u32,
    0x4a4a4a4au32,
    0x0d0d0d0du32,
    0x2d2d2d2du32,
    0xe5e5e5e5u32,
    0x7a7a7a7au32,
    0x9f9f9f9fu32,
    0x93939393u32,
    0xc9c9c9c9u32,
    0x9c9c9c9cu32,
    0xefefefefu32,
    0xa0a0a0a0u32,
    0xe0e0e0e0u32,
    0x3b3b3b3bu32,
    0x4d4d4d4du32,
    0xaeaeaeaeu32,
    0x2a2a2a2au32,
    0xf5f5f5f5u32,
    0xb0b0b0b0u32,
    0xc8c8c8c8u32,
    0xebebebebu32,
    0xbbbbbbbbu32,
    0x3c3c3c3cu32,
    0x83838383u32,
    0x53535353u32,
    0x99999999u32,
    0x61616161u32,
    0x17171717u32,
    0x2b2b2b2bu32,
    0x04040404u32,
    0x7e7e7e7eu32,
    0xbabababau32,
    0x77777777u32,
    0xd6d6d6d6u32,
    0x26262626u32,
    0xe1e1e1e1u32,
    0x69696969u32,
    0x14141414u32,
    0x63636363u32,
    0x55555555u32,
    0x21212121u32,
    0x0c0c0c0cu32,
    0x7d7d7d7du32,
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
    let mut i = 0;

    //as i used to access rcon index let be safe here for ++i code
    let mut j: usize = 0;
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
            j = i + 1;
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
            j = i + 1;
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

            j = i + 1;
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
    let mut nr: i32;
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

pub fn rijndaelDecrypt(mut rk: &[u32], Nr: i32, ct: &[u8; 16], pt: &mut [u8; 16]) {
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
        if (Nr > 10) {
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
            if (Nr > 12) {
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
        rk += Nr << 2;
    }

    #[cfg(not(FULL_UNROLL))]
    {
        /* Nr - 1 full rounds: */
        r = Nr >> 1;
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
            // rk += 8; == &rk[8..] ?
            rk = &rk[8..];

            if (--r == 0) {
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

pub fn rijndaelEncrypt(mut rk: &[u32], Nr: i32, pt: &[u8; 16], ct: &mut [u8; 16]) {
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

        if Nr > 10 {
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
            if Nr > 12 {
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
        rk += Nr << 2;

        //end of FULL_UNROLL
    }

    #[cfg(not(FULL_UNROLL))]
    {
        r = Nr >> 1;
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
    ctx.Nr = rounds;
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
    ctx.Nr = rounds;
    ctx.enc_only = 0;
    return 0;
}

pub fn rijndael_decrypt(ctx: &RijndaelCtx, src: &[u8], dst: &mut [u8]) {
    rijndaelDecrypt(
        &ctx.dk,
        ctx.Nr,
        src.try_into().unwrap(),
        dst.try_into().unwrap(),
    );
}

pub fn rijndael_encrypt(ctx: &RijndaelCtx, src: &[u8], dst: &mut [u8]) {
    rijndaelEncrypt(
        &ctx.ek,
        ctx.Nr,
        src.try_into().unwrap(),
        dst.try_into().unwrap(),
    );
}

pub fn AES_set_key(ctx: &mut AES_ctx, key: &[u8], bits: i32) -> i32 {
    let mut ctx: RijndaelCtx = (*ctx).into();
    return rijndael_set_key(&mut ctx, key, bits);
}

pub fn AES_decrypt(ctx: &AES_ctx, src: &[u8], dst: &mut [u8]) {
    return rijndaelDecrypt(
        &ctx.dk,
        ctx.Nr,
        src.try_into().unwrap(),
        dst.try_into().unwrap(),
    );
}

pub fn AES_encrypt(ctx: &AES_ctx, src: &[u8], dst: &mut [u8]) {
    return rijndaelEncrypt(
        &ctx.ek,
        ctx.Nr,
        src.try_into().unwrap(),
        dst.try_into().unwrap(),
    );
}

pub fn xor_128(a: &[u8], b: &[u8], out: &mut [u8]) {
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
}

pub fn AES_cbc_encrypt(ctx: &AES_ctx, src: &[u8], dst: &mut [u8], size: usize) {
    let mut block_buff = [0u8; 16];

    for i in (0..size).step_by(16) {
        // step 1: copy block to dst
        dst[i..(i + 16)].copy_from_slice(&src[i..(i + 16)]);

        // step 2: XOR with previous block
        if i != 0 {
            xor_128(
                &dst[(i - 16)..i],
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

pub fn AES_cbc_decrypt(ctx: &AES_ctx, src: &[u8], dst: &mut [u8], size: usize) {
    let mut block_buff = [0u8; 16];
    let mut block_buff_previous = [0u8; 16];

    block_buff.copy_from_slice(&src[..16]);
    block_buff_previous.copy_from_slice(&src[..16]);
    AES_decrypt(ctx, &src[..16], &mut dst[..16]);

    for i in (16..size).step_by(16) {
        let current_block = &src[i..(i + 16)];

        block_buff.copy_from_slice(current_block);
        dst[i..(i + 16)].copy_from_slice(current_block);

        AES_decrypt(ctx, &mut dst[i..(i + 16)], &mut dst[i..(i + 16)]);
        xor_128(
            &mut dst[i..(i + 16)],
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

pub fn generate_subkey(ctx: &AES_ctx, mut k1: &mut [u8], mut k2: &mut [u8]) {
    let mut l = [0u8; 16];
    let mut z = [0u8; 16];
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

pub fn AES_CMAC(ctx: &mut AES_ctx, input: &[u8], length: usize, mac: &mut [u8]) {
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

pub struct SHA1Context {
    Message_Digest: [u32; 5], // Message Digest (output)
    Length_Low: u32,          // Message length in bits
    Length_High: u32,         // Message length in bits
    Message_Block: [u8; 64],  // 512-bit message blocks
    Message_Block_Index: i32, // Index into message block array
    Computed: i32,            // Is the digest computed?
    Corrupted: i32,           // Is the message digest corrupted?
}

// Function prototypes
//fn SHA1ProcessMessageBlock(context: &mut SHA1Context);
//fn SHA1PadMessage(context: &mut SHA1Context);

// SHA1Reset function
pub fn SHA1Reset(context: &mut SHA1Context) {
    context.Length_Low = 0;
    context.Length_High = 0;
    context.Message_Block_Index = 0;
    context.Message_Digest[0] = 0x67452301;
    context.Message_Digest[1] = 0xEFCDAB89;
    context.Message_Digest[2] = 0x98BADCFE;
    context.Message_Digest[3] = 0x10325476;
    context.Message_Digest[4] = 0xC3D2E1F0;

    context.Computed = 0;
    context.Corrupted = 0;
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
pub fn SHA1Result(context: &mut SHA1Context) -> i32 {
    if context.Corrupted != 0 {
        return 0;
    }

    if context.Computed == 0 {
        sha1_pad_message(context);
        context.Computed = 1;
    }

    return 1
}

pub fn SHA1Input(context: &mut SHA1Context, message_array: &[u8], length: usize) {
    if length == 0 {
        return;
    }

    // if we go to c standard if(int) is considered anything that not 0 is true and 0 is false
    // correct me on this one
    if context.Computed != 0 || context.Corrupted != 0{
        context.Corrupted = 1;
        return;
    }

    for &byte in message_array.iter().take(length) {
        context.Message_Block[context.Message_Block_Index as usize] = byte;

        context.Length_Low = context.Length_Low.wrapping_add(8);
        context.Length_Low &= 0xFFFFFFFF; // Force it to 32 bits
        if context.Length_Low == 0 {
            context.Length_High = context.Length_High.wrapping_add(1);
            context.Length_High &= 0xFFFFFFFF; // Force it to 32 bits
            if context.Length_High == 0 {
                // Message is too long
                context.Corrupted = 1;
            }
        }

        context.Message_Block_Index += 1;
        if context.Message_Block_Index == 64 {
            SHA1ProcessMessageBlock(context);
        }
    }
}

fn SHA1ProcessMessageBlock(context: &mut SHA1Context) {
    const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
    let mut t: usize;
    let mut temp: u32;
    let mut W: [u32; 80] = [0; 80];
    let mut A: u32;
    let mut B: u32;
    let mut C: u32;
    let mut D: u32;
    let mut E: u32;

    for t in 0..16 {
        W[t] = (context.Message_Block[t * 4] as u32) << 24
            | (context.Message_Block[t * 4 + 1] as u32) << 16
            | (context.Message_Block[t * 4 + 2] as u32) << 8
            | (context.Message_Block[t * 4 + 3] as u32);
    }

    for t in 16..80 {
        W[t] = sha1_circular_shift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
    }

    A = context.Message_Digest[0];
    B = context.Message_Digest[1];
    C = context.Message_Digest[2];
    D = context.Message_Digest[3];
    E = context.Message_Digest[4];

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

    context.Message_Digest[0] = (context.Message_Digest[0] + A) & 0xFFFFFFFF;
    context.Message_Digest[1] = (context.Message_Digest[1] + B) & 0xFFFFFFFF;
    context.Message_Digest[2] = (context.Message_Digest[2] + C) & 0xFFFFFFFF;
    context.Message_Digest[3] = (context.Message_Digest[3] + D) & 0xFFFFFFFF;
    context.Message_Digest[4] = (context.Message_Digest[4] + E) & 0xFFFFFFFF;
    context.Message_Block_Index = 0;
}

fn sha1_pad_message(context: &mut SHA1Context) {
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if context.Message_Block_Index > 55 {
        context.Message_Block[context.Message_Block_Index as usize] = 0x80;
        context.Message_Block_Index += 1;
        while context.Message_Block_Index < 64 {
            context.Message_Block[context.Message_Block_Index as usize] = 0;
            context.Message_Block_Index += 1;
        }

        SHA1ProcessMessageBlock(context);

        while context.Message_Block_Index < 56 {
            context.Message_Block[context.Message_Block_Index as usize] = 0;
            context.Message_Block_Index += 1;
        }
    } else {
        context.Message_Block[context.Message_Block_Index as usize] = 0x80;
        context.Message_Block_Index += 1;
        while context.Message_Block_Index < 56 {
            context.Message_Block[context.Message_Block_Index as usize] = 0;
            context.Message_Block_Index += 1;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context.Message_Block[56] = (context.Length_High >> 24) as u8;
    context.Message_Block[57] = (context.Length_High >> 16) as u8;
    context.Message_Block[58] = (context.Length_High >> 8) as u8;
    context.Message_Block[59] = context.Length_High as u8;
    context.Message_Block[60] = (context.Length_Low >> 24) as u8;
    context.Message_Block[61] = (context.Length_Low >> 16) as u8;
    context.Message_Block[62] = (context.Length_Low >> 8) as u8;
    context.Message_Block[63] = context.Length_Low as u8;

    SHA1ProcessMessageBlock(context);
}

pub fn aes_cmac_forge(ctx: &mut AES_ctx, input: &[u8], length: i32, forge: &mut [u8]) {
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
