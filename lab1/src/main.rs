mod utils;
mod consts;
mod md5;
mod md5_attack;
mod task2;
mod task3;

fn main() {   
    task2::run();
    task3::multi_thread_find_m1_m1_p();
}
