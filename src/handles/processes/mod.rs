pub mod cronh;
mod proch;
mod svch;

use crate::core::Registry;

pub fn register_processes(reg: &mut Registry) {
    cronh::register(reg);
    proch::register(reg);
    svch::register(reg);
}