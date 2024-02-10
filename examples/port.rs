
use std::net::TcpListener;

fn main() {
    get_available_port();
//     if let Some(available_port) = get_available_port() {
//         println!("port `{}` is available", available_port);
//     }
}

// fn get_available_port() -> Option<u16> {
fn get_available_port() {
    for p in 20..90 {
        println!("{}: {}", p, port_is_available(p));
        // if port_is_available(p) == false {
        //     println!("{} avail", p);
        // }
    }
    // (6000..9000)
    //     .find(|port| port_is_available(*port))
    // (6000..9000).into_iter().map(|p| {
    //     println!("{}: avail", p);
    // })
}

fn port_is_available(port: u16) -> bool {
    // match TcpListener::bind(("127.0.0.1", port)) {
    TcpListener::bind(("192.168.1.97", port)).is_ok()
    // match TcpListener::bind(("192.168.1.97", port)) {
    //     Ok(_) => true,
    //     Err(_) => false,
    // }
}
