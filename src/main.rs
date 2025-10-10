pub mod action;
pub mod app;
pub mod cli;
pub mod components;
pub mod config;
pub mod dns_cache;
pub mod mode;
pub mod privilege;
pub mod tui;
pub mod utils;
pub mod enums;
pub mod layout;
pub mod widgets;

use clap::Parser;
use cli::Cli;
use color_eyre::eyre::Result;

use crate::{
  app::App,
  utils::{initialize_logging, initialize_panic_handler},
};

async fn tokio_main() -> Result<()> {
  initialize_logging()?;

  initialize_panic_handler()?;

  // Warn if not running with privileges (non-fatal, operations will fail with better errors)
  if !privilege::has_network_privileges() {
    eprintln!("WARNING: Running without elevated privileges.");
    eprintln!("Some network operations may fail.");
    eprintln!("For full functionality, run with sudo or set appropriate capabilities.");
    eprintln!();
  }

  let args = Cli::parse();
  let mut app = App::new(args.tick_rate, args.frame_rate)?;
  app.run().await?;

  Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
  if let Err(e) = tokio_main().await {
    eprintln!("{} error: Something went wrong", env!("CARGO_PKG_NAME"));
    Err(e)
  } else {
    Ok(())
  }
}
