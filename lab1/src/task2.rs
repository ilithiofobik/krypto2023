use super::utils::{str_to_bytes, verify};

pub fn run() {
    let m0   = str_to_bytes("2dd31d1 c4eee6c5  69a3d69 5cf9af98 87b5ca2f ab7e4612 3e580440 897ffbb8
    634ad55  2b3f409 8388e483 5a417125 e8255108 9fc9cdf7 f2bd1dd9 5b3c3780");
    let m1   = str_to_bytes("d11d0b96 9c7b41dc f497d8e4 d555655a c79a7335  cfdebf0 66f12930 8fb109d1
    797f2775 eb5cd530 baade822 5c15cc79 ddcb74ed 6dd3c55f d80a9bb1 e3a7cc35");
    let m0_p = str_to_bytes("2dd31d1 c4eee6c5 69a3d69 5cf9af98 7b5ca2f ab7e4612 3e580440 897ffbb8
    634ad55 2b3f409 8388e483 5a41f125 e8255108 9fc9cdf7 72bd1dd9 5b3c3780");
    let m1_p = str_to_bytes("d11d0b96 9c7b41dc f497d8e4 d555655a 479a7335 cfdebf0 66f12930 8fb109d1
    797f2775 eb5cd530 baade822 5c154c79 ddcb74ed 6dd3c55f 580a9bb1 e3a7cc35");
    assert!(verify(&m0, &m1, &m0_p, &m1_p));
    if verify(&m0, &m1, &m0_p, &m1_p) {
        println!("Success!");
    } else {
        println!("Fail!");
    }
}