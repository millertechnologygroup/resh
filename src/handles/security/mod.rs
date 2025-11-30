mod certh;
pub mod firewallh;
mod secreth;
mod userh;

use crate::core::Registry;

pub fn register_security(reg: &mut Registry) {
    certh::register(reg);
    firewallh::register(reg);
    secreth::register(reg);
    userh::register(reg);
}