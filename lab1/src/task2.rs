use super::md5;
use super::md5_attack;

fn str_to_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for word in s.split_ascii_whitespace() {
        let bytes = u32::from_str_radix(word, 16).unwrap().to_le_bytes();
        for byte in bytes.into_iter() {
            v.push(byte);
        }
    }
    v   
}

fn find_m1_m1_p(m0: &Vec<u8>, m0_p: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut found = false;

    while !found {

    }

    let mut context = md5::Context::new();
    context.consume(m0);
    //context.consume(m1);
    let digest = context.compute();

    let mut context_p = md5::Context::new();
    context_p.consume(m0_p);
    //context_p.consume(m1_p);
    let digest_p = context_p.compute();
    
    println!("m  -> {:x}", digest);
    println!("m' -> {:x}", digest_p);
    //format!("{:x}", digest) == format!("{:x}", digest_p) 

    (vec![], vec![])
}

pub fn run() {

}