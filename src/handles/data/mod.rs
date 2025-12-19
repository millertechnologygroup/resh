mod cacheh;
mod config;
pub mod dbh;
pub mod eventh;
pub mod logh;
mod mqh;

use crate::core::Registry;

pub fn register_data(reg: &mut Registry) {
    cacheh::register(reg);
    config::register(reg);
    dbh::register(reg);
    eventh::register(reg);
    logh::register(reg);
    mqh::register(reg);
}