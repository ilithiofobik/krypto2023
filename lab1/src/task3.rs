use super::md5_attack::{transform_attack};
use super::md5::{Context, transform};

use fastrand::{Rng};
use std::thread;

fn rand_m1(m1: &mut [u32; 16], rng: &Rng) {
    for word in m1.iter_mut().take(16) {
        *word = rng.u32(..);
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

fn m0_p_init(context: &mut Context) {
    context.count[0] = 0;
    context.count[1] = 0;

    context.state[0] = 0xd2589324;
    context.state[1] = 0xb293d7ca;
    context.state[2] = 0xac06dc54;
    context.state[3] = 0xa2c5be06;
}

fn find_m1_m1_p(seed: u64) -> ([u32; 16], [u32; 16]) {
    let mut found = false;

    let mut m1= [0u32; 16];
    let mut m1_p= [0u32; 16];
    
    let rng = fastrand::Rng::with_seed(seed);
    let mut context1 = Context::new();
    let mut context2 = Context::new();

    while !found {
        m0_init(&mut context1);
        m0_p_init(&mut context2);

        rand_m1(&mut m1, &rng);

        transform_attack(&mut context1.state, &mut m1);

        m1_p.copy_from_slice(&m1);
        m1_p[4]  = m1_p[4].wrapping_add(0x80);
        m1_p[11] = m1_p[11].wrapping_sub(0x20);
        m1_p[14] = m1_p[14].wrapping_add(0x80);

        transform(&mut context2.state, &m1_p);        

        found = context1.state == context2.state;
    }

    println!("m1: {:x?}", m1);
    println!("m1_p: {:x?}", m1_p);

    (m1, m1_p)
}

pub fn multi_thread_find_m1_m1_p() {
    let num = num_cpus::get();
    let items = vec![0; num];

    let threads: Vec<_> = items
        .into_iter()
        .map(|n| {
            thread::spawn(move || {
                find_m1_m1_p(n);
            })
        })
        .collect();

    for handle in threads {
        handle.join().unwrap()
    }
}