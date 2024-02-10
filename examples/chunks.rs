use cidr::Ipv4Cidr;
use std::net::Ipv4Addr;
use tokio::task;
use std::time::Duration;

fn ping(ip: Ipv4Addr) -> Result<String, String> {
    // println!("pinging ip - {}", ip);
    Ok(ip.to_string())
}

#[tokio::main]
async fn main() {

    let pool_size = 8;
    let mut ips: Vec<Ipv4Addr> = Vec::new();

    let cidr_range = "192.168.1.0/24"; // Replace with your CIDR range
    match cidr_range.parse::<Ipv4Cidr>() {
        Ok(ip_cidr) => {
            for ip in ip_cidr.iter() {
                ips.push(ip.address());
            }
        }
        Err(e) => {
            eprintln!("Error parsing CIDR range: {}", e);
        }
    }

    // println!("{:?}", ips);
    
    let ip_chunks: Vec<_> = ips.chunks(pool_size).collect();
    for chunk in ip_chunks {
        // println!("{:?}", chunk);
        let tasks: Vec<_> = chunk.iter().map(|&ip| {
            let closure = || async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                match ping(ip) {
                    Ok(res) => {
                        println!("{} ping done", res);
                    }
                    Err(err) => {
                        println!("{:?} error", err);
                    }
                }
            };
            task::spawn(closure())
        }).collect();

        for task in tasks {
            task.await.unwrap();
            // match task.await {
            //     Ok(_) => {}
            //     Err(_) => {}
            // };
        }
    }
}

