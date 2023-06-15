// Copyright 2007,2008,2010  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt


// Modified for Kirk engine by setting single curve and internal function
// to support Kirk elliptic curve options.- July 2011
// Simplified for use by Kirk Engine since it has only 1 curve

// ported to rust dunno the usefullness of this code ported to rust may investigate later
// need for ecdsa implementation that i rarely touch on PSP so lets port the available public one
// need to investigate this elliptic curve later by writing its harness test also
use std::ptr;
use crate::bn::*;

struct Point {
    x: [u8; 20],
    y: [u8; 20],
}

const ec_p :[u8;20];
const ec_a :[u8;20];
const ec_b :[u8;20];
const ec_N :[u8;21];

const ec_G : Point;  // mon
const ec_Q : Point;  // mon
const ec_k :[u8;21];

fn hex_dump(str: Option<&str>, buf: &[u8], size: usize) {
    if let Some(s) = str {
        println!("{}:", s);
    }

    for i in 0..size {
        if i % 32 == 0 {
            println!("\n{:04X}:", i);
        }
        print!(" {:02X}", buf[i]);
    }

    println!("\n");
}

fn elt_copy(d: &mut [u8], a: &[u8]) {
    d.copy_from_slice(&a[..20]);
}

fn elt_zero(d: &mut [u8]) {
    unsafe {
        ptr::write_bytes(d.as_mut_ptr(), 0, 20);
    }
}

// assume int is i32
fn elt_is_zero(d: &[u8]) -> i32 {
    for &byte in d {
        if byte != 0 {
            return 0;
        }
    }
    1
}

fn elt_add(d: &mut [u8], a: &[u8], b: &[u8]) {
    bn_add(d, a, b, ec_p, 20);
}

fn elt_sub(d: &mut [u8], a: &[u8], b: &[u8]) {
    bn_sub(d, a, b, ec_p, 20);
}

fn elt_mul(d: &mut [u8], a: &[u8], b: &[u8]) {
    bn_mon_mul(d, a, b, ec_p, 20);
}

fn elt_square(d: &mut [u8], a: &[u8]) {
    elt_mul(d, a, a);
}

fn elt_inv(d: &mut [u8], a: &[u8]) {
    let mut s = [0u8; 20];
    elt_copy(&mut s, a);
    bn_mon_inv(d, &s, ec_p, 20);
}

fn point_to_mon(p: &mut Point) {
    bn_to_mon(&mut p.x, ec_p, 20);
    bn_to_mon(&mut p.y, ec_p, 20);
}


fn point_from_mon(p: &mut Point) {
    bn_from_mon(&mut p.x, ec_p, 20);
    bn_from_mon(&mut p.y, ec_p, 20);
}

fn point_is_on_curve(p: &[u8]) -> i32 {
    let mut s = [0u8; 20];
    let mut t = [0u8; 20];
    let x = &p[..20];
    let y = &p[20..];

    elt_square(&mut t, x);
    elt_mul(&mut s, &t, x);

    elt_mul(&mut t, x, &ec_a);
    elt_add(&mut s, &s, &t);

    elt_add(&mut s, &s, &ec_b);

    elt_square(&mut t, y);
    elt_sub(&mut s, &s, &t);

    elt_is_zero(&s)
}

fn point_zero(p: &mut point) {
    elt_zero(&mut p.x);
    elt_zero(&mut p.y);
}

fn point_is_zero(p: &point) -> i32 {
    elt_is_zero(&p.x) && elt_is_zero(&p.y)
}

fn point_double(r: &mut point, p: &point) {
    let mut s = [0u8; 20];
    let mut t = [0u8; 20];
    let pp = *p;
    let px = &pp.x;
    let py = &pp.y;
    let rx = &mut r.x;
    let ry = &mut r.y;

    if elt_is_zero(py) {
        point_zero(r);
        return;
    }

    elt_square(&mut t, px);     // t = px*px
    elt_add(&mut s, &t, &t);    // s = 2*px*px
    elt_add(&mut s, &s, &t);    // s = 3*px*px
    elt_add(&mut s, &s, &ec_a); // s = 3*px*px + a
    elt_add(&mut t, py, py);    // t = 2*py
    elt_inv(&mut t, &t);        // t = 1/(2*py)
    elt_mul(&mut s, &s, &t);    // s = (3*px*px+a)/(2*py)

    elt_square(rx, &s);         // rx = s*s
    elt_add(&mut t, px, px);    // t = 2*px
    elt_sub(rx, &rx, &t);       // rx = s*s - 2*px

    elt_sub(&mut t, px, rx);    // t = -(rx-px)
    elt_mul(ry, &s, &t);        // ry = -s*(rx-px)
    elt_sub(ry, ry, py);        // ry = -s*(rx-px) - py
}


fn point_add(r: &mut point, p: &point, q: &point) {
    let mut s = [0u8; 20];
    let mut t = [0u8; 20];
    let mut u = [0u8; 20];
    let pp = *p;
    let qq = *q;
    let px = &pp.x;
    let py = &pp.y;
    let qx = &qq.x;
    let qy = &qq.y;
    let rx = &mut r.x;
    let ry = &mut r.y;

    if point_is_zero(&pp) {
        elt_copy(rx, qx);
        elt_copy(ry, qy);
        return;
    }

    if point_is_zero(&qq) {
        elt_copy(rx, px);
        elt_copy(ry, py);
        return;
    }

    elt_sub(&mut u, qx, px);

    if elt_is_zero(&u) {
        elt_sub(&mut u, qy, py);
        if elt_is_zero(&u) {
            point_double(r, &pp);
        } else {
            point_zero(r);
        }
        return;
    }

    elt_inv(&mut t, &u);      // t = 1/(qx-px)
    elt_sub(&mut u, qy, py);  // u = qy-py
    elt_mul(&mut s, &t, &u);  // s = (qy-py)/(qx-px)

    elt_square(rx, &s);       // rx = s*s
    elt_add(&mut t, px, qx);  // t = px+qx
    elt_sub(rx, &rx, &t);     // rx = s*s - (px+qx)

    elt_sub(&mut t, px, rx);  // t = -(rx-px)
    elt_mul(ry, &s, &t);      // ry = -s*(rx-px)
    elt_sub(ry, ry, py);      // ry = -s*(rx-px) - py
}


fn point_mul(d: &mut point, a: &[u8], b: &point) {
  let mut mask: u8;

  point_zero(d);

  for i in 0..21 {
      mask = 0x80;

      while mask != 0 {
          point_double(d, d);
          if (a[i] & mask) != 0 {
              point_add(d, d, b);
          }
          mask >>= 1;
      }
  }
}

fn generate_ecdsa(out_r: &mut [u8], out_s: &mut [u8], k: &[u8], hash: &[u8]) {
  let mut e: [u8; 21] = [0; 21];
  let mut kk: [u8; 21] = [0; 21];
  let mut m: [u8; 21] = [0; 21];
  let mut R: [u8; 21] = [0; 21];
  let mut S: [u8; 21] = [0; 21];
  let mut minv: [u8; 21] = [0; 21];
  let mut mG: Point = Point::default(); // Assuming Point struct is defined

  e[0] = 0;
  R[0] = 0;
  S[0] = 0;
  e[1..].copy_from_slice(&hash[..20]);
  bn_reduce(&mut e, &ec_N, 21); // Assuming bn_reduce function is defined

  // R = (mG).x

  // Added call back to kirk PRNG - July 2011
  kirk_CMD14(&mut m[1..], 20);
  m[0] = 0;

  point_mul(&mut mG, &m, &ec_G); // Assuming point_mul and point_from_mon functions are defined
  point_from_mon(&mut mG);
  R[0] = 0;
  elt_copy(&mut R[1..], &mG.x); // Assuming elt_copy function is defined

  // S = m**-1 * (e + Rk) (mod N)

  bn_copy(&mut kk, &k, 21); // Assuming bn_copy function is defined
  bn_reduce(&mut kk, &ec_N, 21);
  bn_to_mon(&mut m, &ec_N, 21);
  bn_to_mon(&mut e, &ec_N, 21);
  bn_to_mon(&mut R, &ec_N, 21);
  bn_to_mon(&mut kk, &ec_N, 21);

  bn_mon_mul(&mut S, &R, &kk, &ec_N, 21); // Assuming bn_mon_mul function is defined
  bn_add(&mut kk, &S, &e, &ec_N, 21); // Assuming bn_add function is defined
  bn_mon_inv(&mut minv, &m, &ec_N, 21); // Assuming bn_mon_inv function is defined
  bn_mon_mul(&mut S, &minv, &kk, &ec_N, 21); // Assuming bn_mon_mul function is defined

  bn_from_mon(&mut R, &ec_N, 21); // Assuming bn_from_mon function is defined
  bn_from_mon(&mut S, &ec_N, 21); // Assuming bn_from_mon function is defined
  outR.copy_from_slice(&R[1..0x21]);
  outS.copy_from_slice(&S[1..0x21]);
}


fn check_ecdsa(Q: &point, inR: &[u8], inS: &[u8], hash: &[u8]) -> i32 {
  let mut Sinv: [u8; 21] = [0; 21];
  let mut e: [u8; 21] = [0; 21];
  let mut R: [u8; 21] = [0; 21];
  let mut S: [u8; 21] = [0; 21];
  let mut w1: [u8; 21] = [0; 21];
  let mut w2: [u8; 21] = [0; 21];
  let mut r1: Point = Point::default(); // Assuming point struct is defined
  let mut r2: Point = Point::default(); // Assuming Point struct is defined
  let mut rr: [u8; 21] = [0; 21];

  e[0] = 0;
  e[1..].copy_from_slice(&hash[..20]);
  bn_reduce(&mut e, &ec_N, 21); // Assuming bn_reduce function is defined
  R[0] = 0;
  R[1..].copy_from_slice(&inR[..20]);
  bn_reduce(&mut R, &ec_N, 21); // Assuming bn_reduce function is defined
  S[0] = 0;
  S[1..].copy_from_slice(&inS[..20]);
  bn_reduce(&mut S, &ec_N, 21); // Assuming bn_reduce function is defined

  bn_to_mon(&mut R, &ec_N, 21); // Assuming bn_to_mon function is defined
  bn_to_mon(&mut S, &ec_N, 21); // Assuming bn_to_mon function is defined
  bn_to_mon(&mut e, &ec_N, 21); // Assuming bn_to_mon function is defined
  bn_mon_inv(&mut Sinv, &S, &ec_N, 21); // Assuming bn_mon_inv function is defined
  bn_mon_mul(&mut w1, &e, &Sinv, &ec_N, 21); // Assuming bn_mon_mul function is defined
  bn_mon_mul(&mut w2, &R, &Sinv, &ec_N, 21); // Assuming bn_mon_mul function is defined
  bn_from_mon(&mut w1, &ec_N, 21); // Assuming bn_from_mon function is defined
  bn_from_mon(&mut w2, &ec_N, 21); // Assuming bn_from_mon function is defined

  point_mul(&mut r1, &w1, &ec_G); // Assuming point_mul function is defined
  point_mul(&mut r2, &w2, &Q); // Assuming point_mul function is defined
  point_add(&mut r1, &r1, &r2); // Assuming point_add function is defined
  point_from_mon(&mut r1); // Assuming point_from_mon function is defined

  rr[0] = 0;
  rr[1..].copy_from_slice(&r1.x[..20]);
  bn_reduce(&mut rr, &ec_N, 21); // Assuming bn_reduce function is defined
  bn_from_mon(&mut R, &ec_N, 21); // Assuming bn_from_mon function is defined
  bn_from_mon(&mut S, &ec_N, 21); // Assuming bn_from_mon function is defined

  bn_compare(&rr, &R, 21) == 0 // Assuming bn_compare function is defined
}

fn ec_priv_to_pub(k: &[u8], Q: &mut [u8]) {
  let mut ec_temp: Point = Point::default(); // Assuming Point struct is defined
  bn_to_mon(&k, &ec_N, 21); // Assuming bn_to_mon function is defined
  point_mul(&mut ec_temp, &k, &ec_G); // Assuming point_mul function is defined
  point_from_mon(&mut ec_temp); // Assuming point_from_mon function is defined
  Q[..20].copy_from_slice(&ec_temp.x);
  Q[20..].copy_from_slice(&ec_temp.y);
}

fn ec_pub_mult(k: &[u8], Q: &mut [u8]) {
    let mut ec_temp: Point = Point::default(); // Assuming Point struct is defined
    point_mul(&mut ec_temp, &k, &ec_Q); // Assuming point_mul function is defined
    point_from_mon(&mut ec_temp); // Assuming point_from_mon function is defined
    Q[..20].copy_from_slice(&ec_temp.x);
    Q[20..].copy_from_slice(&ec_temp.y);
}

fn ecdsa_set_curve(p: &[u8], a: &[u8], b: &[u8], N: &[u8], Gx: &[u8], Gy: &[u8]) -> i32 {
    ec_p.copy_from_slice(&p);
    ec_a.copy_from_slice(&a);
    ec_b.copy_from_slice(&b);
    ec_N.copy_from_slice(&N);

    bn_to_mon(&mut ec_a, &ec_p, 20); // Assuming bn_to_mon function is defined
    bn_to_mon(&mut ec_b, &ec_p, 20); // Assuming bn_to_mon function is defined

    ec_G.x.copy_from_slice(&Gx);
    ec_G.y.copy_from_slice(&Gy);
    point_to_mon(&mut ec_G); // Assuming point_to_mon function is defined

    0
}

fn ecdsa_set_pub(Q: &[u8]) {
    ec_Q.x.copy_from_slice(&Q[..20]);
    ec_Q.y.copy_from_slice(&Q[20..]);
    point_to_mon(&mut ec_Q); // Assuming point_to_mon function is defined
}

fn ecdsa_set_priv(ink: &[u8]) {
    let mut k: [u8; 21] = [0; 21];
    k[0] = 0;
    k[1..].copy_from_slice(&ink[..20]);
    bn_reduce(&mut k, &ec_N, 21); // Assuming bn_reduce function is defined

    ec_k.copy_from_slice(&k);
}

fn ecdsa_verify(hash: &[u8], R: &[u8], S: &[u8]) -> i32 {
    check_ecdsa(&ec_Q, &R, &S, &hash) // Assuming check_ecdsa function is defined
}

fn ecdsa_sign(hash: &[u8], R: &mut [u8], S: &mut [u8]) {
    generate_ecdsa(&mut R, &mut S, &ec_k, &hash); // Assuming generate_ecdsa function is defined
}

fn point_is_on_curve(p: &[u8]) -> i32 {
    let mut s: [u8; 20] = [0; 20];
    let mut t: [u8; 20] = [0; 20];
    let x = &p[..20];
    let y = &p[20..];

    elt_square(&mut t, &x);
    elt_mul(&mut s, &t, &x); // s = x^3

    elt_mul(&mut t, &x, &ec_a);
    elt_add(&mut s, &s, &t); // s = x^3 + a * x

    elt_add(&mut s, &s, &ec_b); // s = x^3 + a * x + b

    elt_square(&mut t, &y); // t = y^2
    elt_sub(&mut s, &s, &t); // is s - t = 0?

    hex_dump("S", &s, 20);
    hex_dump("T", &t, 20);

    elt_is_zero(&s)
}

fn dump_ecc() {
    hex_dump("P", &ec_p, 20);
    hex_dump("a", &ec_a, 20);
    hex_dump("b", &ec_b, 20);
    hex_dump("N", &ec_N, 21);
    hex_dump("Gx", &ec_G.x, 20);
    hex_dump("Gy", &ec_G.y, 20);
}
