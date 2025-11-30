mod gith;
pub mod pkgh;
pub mod systemh;

use crate::core::Registry;

pub fn register_system(reg: &mut Registry) {
    gith::register(reg);
    pkgh::register(reg);
    systemh::register(reg);
}