pub fn transform_attack(state: &mut [u32; 4], input: &mut [u32; 16]) {
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    let (mut a_prev, mut b_prev, mut c_prev, mut d_prev) = (state[0], state[1], state[2], state[3]);

    macro_rules! add(
        ($a:expr, $b:expr) => ($a.wrapping_add($b));
    );
    macro_rules! sub(
        ($a:expr, $b:expr) => ($a.wrapping_sub($b));
    );
    macro_rules! rotate_left(
        ($x:expr, $n:expr) => (($x << $n) | ($x >> (32 - $n)));
    );
    macro_rules! rotate_right(
        ($x:expr, $n:expr) => (($x >> $n) | ($x << (32 - $n)));
    );
    {
        macro_rules! FIX_0(
            ($x:expr, $mask:expr) => ($x &= !$mask);
        );
        macro_rules! FIX_1(
            ($x:expr, $mask:expr) => ($x |= $mask);
        );
        macro_rules! FIX_PREV(
            ($x:expr, $mask:expr, $x_prev:expr) => ($x = ($x & !$mask) | ($x_prev & $mask));
        );
        macro_rules! F(
            ($x:expr, $y:expr, $z:expr) => (($x & $y) | (!$x & $z));
        );
        macro_rules! T(
            ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => ({
                $a = add!(add!(add!($a, F!($b, $c, $d)), $x), $ac);
                $a = rotate_left!($a, $s);
                $a = add!($a, $b);
            });
        );
        macro_rules! T_INV(
            ($a:expr, $a_prev:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => ({
                $x = sub!($a, $b);
                $x = rotate_right!($x, $s);
                $x = sub!($x, add!(add!(F!($b, $c, $d), $ac), $a_prev));
            });
        );

        const S1: u32 =  7;
        const S2: u32 = 12;
        const S3: u32 = 17;
        const S4: u32 = 2;

        const A1_0 : u32 = 0x0a000820;
        const A1_1 : u32 = 0x84200000;
        const D1_0 : u32 = 0x02208026;
        const D1_1 : u32 = 0x8c000800;
        const D1_P : u32 = 0x701f10c0;
        const C1_0 : u32 = 0x40201080;
        const C1_1 : u32 = 0xbe1f0966;
        const C1_P : u32 = 0x00000018;
        const B1_0 : u32 = 0x443b19ee;
        const B1_1 : u32 = 0xba040010;
        const B1_P : u32 = 0x00000601;
        const A2_0 : u32 = 0xb41011af;
        const A2_1 : u32 = 0x482f0e50;
        const D2_0 : u32 = 0x9a1113a9;
        const D2_1 : u32 = 0x04220c56;
        const C2_0 : u32 = 0x083201c0;
        const C2_1 : u32 = 0x96011e01;
        const C2_P : u32 = 0x01808000;
        const B2_0 : u32 = 0x1b810001;
        const B2_1 : u32 = 0x843283c0;
        const B2_P : u32 = 0x00000002;
        const A3_0 : u32 = 0x03828202;
        const A3_1 : u32 = 0x9c0101c1;
        const A3_P : u32 = 0x00001000;
        const D3_0 : u32 = 0x00041003;
        const D3_1 : u32 = 0x878383c0;
        const C3_0 : u32 = 0x00021000;
        const C3_1 : u32 = 0x800583c3;
        const C3_P : u32 = 0x00086000;
        const B3_0 : u32 = 0x0007e000;
        const B3_1 : u32 = 0x80081080;
        const B3_P : u32 = 0x7f000000;
        const A4_0 : u32 = 0xc0000080;
        const A4_1 : u32 = 0x3f0fe008;
        const D4_0 : u32 = 0xbf040000;
        const D4_1 : u32 = 0x400be088;
        const C4_0 : u32 = 0x82008008;
        const C4_1 : u32 = 0x7d000000;
        const B4_0 : u32 = 0x80000000;
        const B4_1 : u32 = 0x20000000;

        T! (a, b, c, d, input[ 0], S1, 3614090360); /* 1 */
        FIX_0!(a,A1_0);
        FIX_1!(a,A1_1);
        T_INV! (a, a_prev, b, c, d, input[ 0], S1, 3614090360);
        a_prev = a;
        
        T! (d, a, b, c, input[ 1], S2, 3905402710); /* 2 */
        FIX_0!(d,D1_0);
        FIX_1!(d,D1_1);
        FIX_PREV!(d,D1_P,a);
        T_INV! (d, d_prev, a, b, c, input[ 1], S2, 3905402710);
        d_prev = d;
      
        T! (c, d, a, b, input[ 2], S3, 606105819); /* 3 */
        FIX_0!(c,C1_0);
        FIX_1!(c,C1_1);
        FIX_PREV!(c,C1_P,d);
        T_INV! (c, c_prev, d, a, b, input[ 2], S3, 606105819);
        c_prev = c;
      
        T! (b, c, d, a, input[ 3], S4, 3250441966); /* 4 */
        FIX_0!(b,B1_0);
        FIX_1!(b,B1_1);
        FIX_PREV!(b,B1_P,c);
        T_INV! (b, b_prev, c, d, a, input[ 3], S4, 3250441966);
        b_prev = b;
      
        T! (a, b, c, d, input[ 4], S1, 4118548399); /* 5 */
        FIX_0!(a,A2_0);
        FIX_1!(a,A2_1);
        T_INV! (a, a_prev, b, c, d, input[ 4], S1, 4118548399);
        a_prev = a;
      
        T! (d, a, b, c, input[ 5], S2, 1200080426); /* 6 */
        FIX_0!(d,D2_0);
        FIX_1!(d,D2_1);
        T_INV! (d, d_prev, a, b, c, input[ 5], S2, 1200080426);
        d_prev = d;
      
        T! (c, d, a, b, input[ 6], S3, 2821735955); /* 7 */
        FIX_0!(c,C2_0);
        FIX_1!(c,C2_1);
        FIX_PREV!(c,C2_P,d);
        T_INV! (c, c_prev, d, a, b, input[ 6], S3, 2821735955);
        c_prev = c;
      
        T! (b, c, d, a, input[ 7], S4, 4249261313); /* 8 */
        FIX_0!(b,B2_0);
        FIX_1!(b,B2_1);
        FIX_PREV!(b,B2_P,c);
        T_INV! (b, b_prev, c, d, a, input[ 7], S4, 4249261313);
        b_prev = b;
      
        T! (a, b, c, d, input[ 8], S1, 1770035416); /* 9 */
        FIX_0!(a,A3_0);
        FIX_1!(a,A3_1);
        FIX_PREV!(a,A3_P,b);
        T_INV! (a, a_prev, b, c, d, input[ 8], S1, 1770035416);
        a_prev = a;
      
        T! (d, a, b, c, input[ 9], S2, 2336552879); /* 10 */
        FIX_0!(d,D3_0);
        FIX_1!(d,D3_1);
        T_INV! (d, d_prev, a, b, c, input[ 9], S2, 2336552879);
        d_prev = d;
      
        T! (c, d, a, b, input[10], S3, 4294925233); /* 11 */
        FIX_0!(c,C3_0);
        FIX_1!(c,C3_1);
        FIX_PREV!(c,C3_P,d);
        T_INV! (c, c_prev, d, a, b, input[10], S3, 4294925233);
        c_prev = c;
      
        T! (b, c, d, a, input[11], S4, 2304563134); /* 12 */
        FIX_0!(b,B3_0);
        FIX_1!(b,B3_1);
        FIX_PREV!(b,B3_P,c);
        T_INV! (b, b_prev, c, d, a, input[11], S4, 2304563134);
        b_prev = b;
      
        T! (a, b, c, d, input[12], S1, 1804603682); /* 13 */
        FIX_0!(a,A4_0);
        FIX_1!(a,A4_1);
        T_INV! (a, a_prev, b, c, d, input[12], S1, 1804603682);
      
        T! (d, a, b, c, input[13], S2, 4254626195); /* 14 */
        FIX_0!(d,D4_0);
        FIX_1!(d,D4_1);
        T_INV! (d, d_prev, a, b, c, input[13], S2, 4254626195);
      
        T! (c, d, a, b, input[14], S3, 2792965006); /* 15 */
        FIX_0!(c,C4_0);
        FIX_1!(c,C4_1);
        T_INV! (c, c_prev, d, a, b, input[14], S3, 2792965006);
      
        T! (b, c, d, a, input[15], S4, 1236535329); /* 16 */
        FIX_0!(b,B4_0);
        FIX_1!(b,B4_1);
        T_INV! (b, b_prev, c, d, a, input[15], S4, 1236535329);
    }
    {
        macro_rules! F(
            ($x:expr, $y:expr, $z:expr) => (($x & $z) | ($y & !$z));
        );
        macro_rules! T(
            ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => ({
                $a = add!(add!(add!($a, F!($b, $c, $d)), $x), $ac);
                $a = rotate_left!($a, $s);
                $a = add!($a, $b);
            });
        );
        const S1: u32 =  5;
        const S2: u32 =  9;
        const S3: u32 = 14;
        const S4: u32 = 20;
        T!(a, b, c, d, input[ 1], S1, 4129170786);
        T!(d, a, b, c, input[ 6], S2, 3225465664);
        T!(c, d, a, b, input[11], S3,  643717713);
        T!(b, c, d, a, input[ 0], S4, 3921069994);
        T!(a, b, c, d, input[ 5], S1, 3593408605);
        T!(d, a, b, c, input[10], S2,   38016083);
        T!(c, d, a, b, input[15], S3, 3634488961);
        T!(b, c, d, a, input[ 4], S4, 3889429448);
        T!(a, b, c, d, input[ 9], S1,  568446438);
        T!(d, a, b, c, input[14], S2, 3275163606);
        T!(c, d, a, b, input[ 3], S3, 4107603335);
        T!(b, c, d, a, input[ 8], S4, 1163531501);
        T!(a, b, c, d, input[13], S1, 2850285829);
        T!(d, a, b, c, input[ 2], S2, 4243563512);
        T!(c, d, a, b, input[ 7], S3, 1735328473);
        T!(b, c, d, a, input[12], S4, 2368359562);
    }
    {
        macro_rules! F(
            ($x:expr, $y:expr, $z:expr) => ($x ^ $y ^ $z);
        );
        macro_rules! T(
            ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => ({
                $a = add!(add!(add!($a, F!($b, $c, $d)), $x), $ac);
                $a = rotate_left!($a, $s);
                $a = add!($a, $b);
            });
        );
        const S1: u32 =  4;
        const S2: u32 = 11;
        const S3: u32 = 16;
        const S4: u32 = 23;
        T!(a, b, c, d, input[ 5], S1, 4294588738);
        T!(d, a, b, c, input[ 8], S2, 2272392833);
        T!(c, d, a, b, input[11], S3, 1839030562);
        T!(b, c, d, a, input[14], S4, 4259657740);
        T!(a, b, c, d, input[ 1], S1, 2763975236);
        T!(d, a, b, c, input[ 4], S2, 1272893353);
        T!(c, d, a, b, input[ 7], S3, 4139469664);
        T!(b, c, d, a, input[10], S4, 3200236656);
        T!(a, b, c, d, input[13], S1,  681279174);
        T!(d, a, b, c, input[ 0], S2, 3936430074);
        T!(c, d, a, b, input[ 3], S3, 3572445317);
        T!(b, c, d, a, input[ 6], S4,   76029189);
        T!(a, b, c, d, input[ 9], S1, 3654602809);
        T!(d, a, b, c, input[12], S2, 3873151461);
        T!(c, d, a, b, input[15], S3,  530742520);
        T!(b, c, d, a, input[ 2], S4, 3299628645);
    }
    {
        macro_rules! F(
            ($x:expr, $y:expr, $z:expr) => ($y ^ ($x | !$z));
        );
        macro_rules! T(
            ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $s:expr, $ac:expr) => ({
                $a = add!(add!(add!($a, F!($b, $c, $d)), $x), $ac);
                $a = rotate_left!($a, $s);
                $a = add!($a, $b);
            });
        );
        const S1: u32 =  6;
        const S2: u32 = 10;
        const S3: u32 = 15;
        const S4: u32 = 21;
        T!(a, b, c, d, input[ 0], S1, 4096336452);
        T!(d, a, b, c, input[ 7], S2, 1126891415);
        T!(c, d, a, b, input[14], S3, 2878612391);
        T!(b, c, d, a, input[ 5], S4, 4237533241);
        T!(a, b, c, d, input[12], S1, 1700485571);
        T!(d, a, b, c, input[ 3], S2, 2399980690);
        T!(c, d, a, b, input[10], S3, 4293915773);
        T!(b, c, d, a, input[ 1], S4, 2240044497);
        T!(a, b, c, d, input[ 8], S1, 1873313359);
        T!(d, a, b, c, input[15], S2, 4264355552);
        T!(c, d, a, b, input[ 6], S3, 2734768916);
        T!(b, c, d, a, input[13], S4, 1309151649);
        T!(a, b, c, d, input[ 4], S1, 4149444226);
        T!(d, a, b, c, input[11], S2, 3174756917);
        T!(c, d, a, b, input[ 2], S3,  718787259);
        T!(b, c, d, a, input[ 9], S4, 3951481745);
    }
    state[0] = add!(state[0], a);
    state[1] = add!(state[1], b);
    state[2] = add!(state[2], c);
    state[3] = add!(state[3], d);
}

