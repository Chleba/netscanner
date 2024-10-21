#[tokio::main(flavor = "current_thread")]
async fn main() {
    let networks = tokio_wifiscanner::scan().await.expect("Cannot scan network");
    for network in networks {
        println!(
            "{} {:15} {:10} {:4} {}",
            network.mac, network.ssid, network.channel, network.signal_level, network.security
        );
    }
}
