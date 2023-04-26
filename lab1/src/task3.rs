use super::md5_attack::{consume_attack, Context};
use fastrand;
use super::utils;

fn rand_m1(m1: &mut Vec<u8>, rng: &fastrand::Rng) {
    for i in 0..64 {
        m1[i] = rng.u8(..);
    }
}

fn m0_init(context: &mut Context) {
    context.count[0] = 0;
    context.count[1] = 0;

    context.state[0] = 0x52589324;
    context.state[1] = 0x3093d7ca;
    context.state[2] = 0x2a06dc54;
    context.state[3] = 0x20c5be06;
  }

fn find_m1_m1_p(m0: &Vec<u8>, m0_p: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut found = false;
    let mut m1   = vec![0u8; 64];
    let mut m1_p = vec![0u8; 64];
    let rng = fastrand::Rng::new();
    let mut context = Context::new();

    while !found {
        // wylosuj m1
        rand_m1(&mut m1, &rng);
        // context na obliczenia po m0
        m0_init(&mut context);
        // m1' = m1 -> przerabiamy m1'
        for i in 0..64 {
            m1_p[i] = m1[i];
        }
        // właściwy atak
        consume_attack(&mut context, &mut m1_p);
        // sprawdzenie czy atak się powiódł
        found = utils::verify(m0, &m1, m0_p, &m1_p);
    }

    (m1, m1_p)
}

fn step2(m0: Vec<u8>, m0_p: Vec<u8>) {
    let (m1, m1_p) = find_m1_m1_p(&m0, &m0_p);
}

pub fn run() {

}