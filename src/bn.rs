// // Copyright 2007,2008,2010  Segher Boessenkool  <segher@kernel.crashing.org>
// // Licensed under the terms of the GNU GPL, version 2
// // http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
// // Updated and simplified for use by Kirk Engine - July 2011
// // dunno the usefullness of convertion this c code into rust may investigate later
// // bn is abbreviation of Big Number if i see correctly from the kirk engine library available in opensource implementation
// use std::ptr;

// fn bn_print(name: &str, a: &[u8]) {
//     print!("{} = ", name);
//     for &byte in a {
//         print!("{:02x}", byte);
//     }
//     println!();
// }

// fn bn_zero(d: &mut [u8]) {
//     unsafe {
//         ptr::write_bytes(d.as_mut_ptr(), 0, d.len());
//     }
// }

// fn bn_copy(d: &mut [u8], a: &[u8]) {
//     d.copy_from_slice(a);
// }

// fn bn_compare(a: &[u8], b: &[u8]) -> i32 {
//     for (&byte_a, &byte_b) in a.iter().zip(b.iter()) {
//         if byte_a < byte_b {
//             return -1;
//         } else if byte_a > byte_b {
//             return 1;
//         }
//     }
//     0
// }

// fn bn_add_1(d: &mut [u8], a: &[u8], b: &[u8]) -> u8 {
//     let n = d.len();
//     let mut c = 0;
//     for i in (0..n).rev() {
//         let dig = u32::from(a[i]) + u32::from(b[i]) + u32::from(c);
//         c = dig >> 8;
//         d[i] = dig as u8;
//     }
//     c as u8
// }

// fn bn_sub_1(d: &mut [u8], a: &[u8], b: &[u8]) -> u8 {
//     let n = d.len();
//     let mut c = 1;
//     for i in (0..n).rev() {
//         let dig = u32::from(a[i]) + 255 - u32::from(b[i]) + u32::from(c);
//         c = dig >> 8;
//         d[i] = dig as u8;
//     }
//     (1 - c) as u8
// }

// fn bn_reduce(d: &mut [u8], n: &[u8]) {
//     if bn_compare(d, n) >= 0 {
//         bn_sub_1(d, d, n);
//     }
// }

// fn bn_add(d: &mut [u8], a: &[u8], b: &[u8], n: &[u8]) {
//     if bn_add_1(d, a, b) != 0 {
//         bn_sub_1(d, d, n);
//     }
//     bn_reduce(d, n);
// }

// fn bn_sub(d: &mut [u8], a: &[u8], b: &[u8], n: &[u8]) {
//     if bn_sub_1(d, a, b) != 0 {
//         bn_add_1(d, d, n);
//     }
// }

// const INV256: [u8; 0x80] = [
//     0x01, 0xab, 0xcd, 0xb7, 0x39, 0xa3, 0xc5, 0xef, 0xf1, 0x1b, 0x3d, 0xa7, 0x29, 0x13, 0x35, 0xdf,
//     0xe1, 0x8b, 0xad, 0x97, 0x19, 0x83, 0xa5, 0xcf, 0xd1, 0xfb, 0x1d, 0x87, 0x09, 0xf3, 0x15, 0xbf,
//     0xc1, 0x6b, 0x8d, 0x77, 0xf9, 0x63, 0x85, 0xaf, 0xb1, 0xdb, 0xfd, 0x67, 0xe9, 0xd3, 0xf5, 0x9f,
//     0xa1, 0x4b, 0x6d, 0x57, 0xd9, 0x43, 0x65, 0x8f, 0x91, 0xbb, 0xdd, 0x47, 0xc9, 0xb3, 0xd5, 0x7f,
//     0x81, 0x2b, 0x4d, 0x37, 0xb9, 0x23, 0x45, 0x6f, 0x71, 0x9b, 0xbd, 0x27, 0xa9, 0x93, 0xb5, 0x5f,
//     0x61, 0x0b, 0x2d, 0x17, 0x99, 0x03, 0x25, 0x4f, 0x51, 0x7b, 0x9d, 0x07, 0x89, 0x73, 0x95, 0x3f,
//     0x41, 0xeb, 0x0d, 0xf7, 0x79, 0xe3, 0x05, 0x2f, 0x31, 0x5b, 0x7d, 0xe7, 0x69, 0x53, 0x75, 0x1f,
//     0x21, 0xcb, 0xed, 0xd7, 0x59, 0xc3, 0xe5, 0x0f, 0x11, 0x3b, 0x5d, 0xc7, 0x49, 0x33, 0x55, 0xff,
// ];

// fn bn_mon_muladd_dig(d: &mut [u8], a: &[u8], b: u8, n: &[u8]) {
//     let n_len = n.len();
//     let mut dig;
//     let mut z = -(d[n_len - 1] + u32::from(a[n_len - 1]) * u32::from(b)) * u32::from(INV256[n[n_len - 1] as usize >> 1]);
//     dig = u32::from(d[n_len - 1]) + u32::from(a[n_len - 1]) * u32::from(b) + u32::from(n[n_len - 1]) * u32::from(z);
//     dig >>= 8;

//     for i in (0..(n_len - 1)).rev() {
//         dig += u32::from(d[i]) + u32::from(a[i]) * u32::from(b) + u32::from(n[i]) * u32::from(z);
//         d[i + 1] = dig as u8;
//         dig >>= 8;
//     }

//     d[0] = dig as u8;
//     dig >>= 8;

//     if dig != 0 {
//         bn_sub_1(d, d, n);
//     }

//     bn_reduce(d, n);
// }

// fn bn_mon_mul(d: &mut [u8], a: &[u8], b: &[u8], n: &[u8]) {
//     let n_len = n.len();
//     let mut t = [0u8; 512];

//     bn_zero(&mut t, n_len);

//     for i in (0..n_len).rev() {
//         bn_mon_muladd_dig(&mut t, a, b[i], n);
//     }

//     bn_copy(d, &t, n_len);
// }

// fn bn_to_mon(d: &mut [u8], n: &[u8]) {
//     let n_len = n.len();

//     for _ in 0..(8 * n_len) {
//         bn_add(d, d, d, n);
//     }
// }

// fn bn_from_mon(d: &mut [u8], n: &[u8]) {
//     let n_len = n.len();
//     let mut t = [0u8; 512];

//     bn_zero(&mut t, n_len);
//     t[n_len - 1] = 1;
//     bn_mon_mul(d, d, &t, n);
// }

// fn bn_mon_exp(d: &mut [u8], a: &[u8], n: &[u8], e: &[u8]) {
//     let n_len = n.len();
//     let en_len = e.len();
//     let mut t = [0u8; 512];
//     let mut mask;

//     bn_zero(d, n_len);
//     d[n_len - 1] = 1;
//     bn_to_mon(d, n);

//     for i in 0..en_len {
//         mask = 0x80;
//         while mask != 0 {
//             bn_mon_mul(&mut t, d, d, n);
//             if (e[i] & mask) != 0 {
//                 bn_mon_mul(d, &t, a, n);
//             } else {
//                 bn_copy(d, &t, n_len);
//             }
//             mask >>= 1;
//         }
//     }
// }

// fn bn_mon_inv(d: &mut [u8], a: &[u8], n: &[u8]) {
//     let n_len = n.len();
//     let mut t = [0u8; 512];
//     let mut s = [0u8; 512];

//     bn_zero(&mut s, n_len);
//     s[n_len - 1] = 2;
//     bn_sub_1(&mut t, n, &s);
//     bn_mon_exp(d, a, n, &t);
// }
