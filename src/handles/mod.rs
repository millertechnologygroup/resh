mod automation;
pub mod data;
mod filesystem;
mod network;
mod pluginh;
mod processes;
mod security;
mod system;


use crate::core::Registry;

pub fn register_all(reg: &mut Registry) {
    automation::register_all(reg);
    data::register_data(reg);
    filesystem::register_filesystem(reg);
    network::register_network(reg);
    processes::register_processes(reg);
    security::register_security(reg);
    system::register_system(reg);
}