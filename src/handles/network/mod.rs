pub mod dnsh;
mod httph;
pub mod mailh;
mod neth;
pub mod sshh;

use crate::core::Registry;

pub fn register_network(reg: &mut Registry) {
    dnsh::register(reg);
    httph::register(reg);
    mailh::register(reg);
    neth::register(reg);
    sshh::register(reg);
}