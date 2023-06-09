use super::md5;

pub fn str_to_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for word in s.split_ascii_whitespace() {
        let bytes = u32::from_str_radix(word, 16).unwrap().to_le_bytes();
        for byte in bytes.into_iter() {
            v.push(byte);
        }
    }
    v   
}

pub fn verify(m0: &Vec<u8>, m1: &Vec<u8>, m0_p: &Vec<u8>, m1_p: &Vec<u8>) -> bool {
    let mut context = md5::Context::new();
    context.consume(m0, false);
    context.consume(m1, false);
    let digest = context.compute();

    let mut context_p = md5::Context::new();
    context_p.consume(m0_p, false);
    context_p.consume(m1_p, false);
    let digest_p = context_p.compute();
    
    println!("m  -> {:x}", digest);
    println!("m' -> {:x}", digest_p);
    digest == digest_p
}