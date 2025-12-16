// Placholder
pub mod backup;
pub mod backuph;
pub mod pluginh;
pub mod templateh;

use crate::core::Registry;

pub fn register_all(reg: &mut Registry) {
    backuph::register(reg);
    pluginh::register(reg);
    templateh::register(reg);
}