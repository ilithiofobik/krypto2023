use super::utils::verify;
use super::consts;

pub fn run() {
    let m0   = consts::m0();
    let m1   = consts::m1();
    let m0_p = consts::m0_p();
    let m1_p = consts::m1_p();

    assert!(verify(&m0, &m1, &m0_p, &m1_p));
    if verify(&m0, &m1, &m0_p, &m1_p) {
        println!("Success!");
    } else {
        println!("Fail!");
    }
}