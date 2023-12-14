// use tokio::net;
// use std::io;
use dns_lookup::getnameinfo;
use std::net::{IpAddr, SocketAddr};

#[tokio::main]
async fn main() {
    // let ip: IpAddr = "192.168.1.237".parse().unwrap();
    let ip: IpAddr = "192.168.1.50".parse().unwrap();
    let port = 22;
    let mut socket: SocketAddr = (ip, port).into();
    let ports = vec![1, 5, 10, 22, 80, 3000, 8080, 5000, 5432, 7000];

    for p in ports {
        socket.set_port(p);
        let (name, service) = match getnameinfo(&socket, 0) {
            Ok((n, s)) => (n, s),
            Err(e) => panic!("fail lookup {:?}", e),
        };
        println!("{:?}, {:?}", name, service);
    }

    // let (name, service) = match getnameinfo(&socket, 0) {
    //     Ok((n, s)) => (n, s),
    //     Err(e) => panic!("fail lookup {:?}", e),
    // };

    // println!("{:?}, {:?}", name, service);
}
