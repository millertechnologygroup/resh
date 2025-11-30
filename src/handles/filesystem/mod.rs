pub mod archiveh;
mod fileh;
mod fs_atomic;
pub mod fsh;
mod snapshot;

use crate::core::Registry;

pub fn register_filesystem(reg: &mut Registry) {
    archiveh::register(reg);
    fileh::register(reg);
    fsh::register(reg);
    snapshot::register(reg);
}