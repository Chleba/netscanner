# tokio-wifiscanner

The project is a simple [tokio](https://tokio.rs) wrapper around [wifiscanner](https://github.com/booyaa/wifiscanner) library.

# Usage

This crate is [on crates.io](https://crates.io/crates/tokio-wifiscanner) and can be
used by adding `tokio-wifiscanner` to the dependencies in your project's `Cargo.toml`.

```toml
[dependencies]
tokio-wifiscanner = "0.2.*"
```

and this to your crate root:

```rust
extern crate tokio_wifiscanner;
```

## Example

```rust
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
 ```

Alternatively if you've cloned the Git repo, you can run the above example
using: `cargo run --example scan`.
