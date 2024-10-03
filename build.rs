
fn main() {
  #[cfg(target_os = "windows")]
  download_windows_npcap_sdk().unwrap();

  let git_output = std::process::Command::new("git").args(["rev-parse", "--git-dir"]).output().ok();
  let git_dir = git_output.as_ref().and_then(|output| {
    std::str::from_utf8(&output.stdout).ok().and_then(|s| s.strip_suffix('\n').or_else(|| s.strip_suffix("\r\n")))
  });

  // Tell cargo to rebuild if the head or any relevant refs change.
  if let Some(git_dir) = git_dir {
    let git_path = std::path::Path::new(git_dir);
    let refs_path = git_path.join("refs");
    if git_path.join("HEAD").exists() {
      println!("cargo:rerun-if-changed={}/HEAD", git_dir);
    }
    if git_path.join("packed-refs").exists() {
      println!("cargo:rerun-if-changed={}/packed-refs", git_dir);
    }
    if refs_path.join("heads").exists() {
      println!("cargo:rerun-if-changed={}/refs/heads", git_dir);
    }
    if refs_path.join("tags").exists() {
      println!("cargo:rerun-if-changed={}/refs/tags", git_dir);
    }
  }

  let git_output =
    std::process::Command::new("git").args(["describe", "--always", "--tags", "--long", "--dirty"]).output().ok();
  let git_info = git_output.as_ref().and_then(|output| std::str::from_utf8(&output.stdout).ok().map(str::trim));
  let cargo_pkg_version = env!("CARGO_PKG_VERSION");

  // Default git_describe to cargo_pkg_version
  let mut git_describe = String::from(cargo_pkg_version);

  if let Some(git_info) = git_info {
    // If the `git_info` contains `CARGO_PKG_VERSION`, we simply use `git_info` as it is.
    // Otherwise, prepend `CARGO_PKG_VERSION` to `git_info`.
    if git_info.contains(cargo_pkg_version) {
      // Remove the 'g' before the commit sha
      let git_info = &git_info.replace('g', "");
      git_describe = git_info.to_string();
    } else {
      git_describe = format!("v{}-{}", cargo_pkg_version, git_info);
    }
  }

  println!("cargo:rustc-env=_GIT_INFO={}", git_describe);
}

#[cfg(target_os = "windows")]
fn download_windows_npcap_sdk() -> anyhow::Result<()> {

  use anyhow::anyhow;

  use std::{
      fs,
      io::{self, Write},
      env,
      path::PathBuf
  };

  use http_req::request;
  use zip::ZipArchive;

  println!("cargo:rerun-if-changed=build.rs");

  // get npcap SDK
  const NPCAP_SDK: &str = "npcap-sdk-1.13.zip";

  let npcap_sdk_download_url = format!("https://npcap.com/dist/{NPCAP_SDK}");
  let cache_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("target");
  let npcap_sdk_cache_path = cache_dir.join(NPCAP_SDK);

  let npcap_zip = match fs::read(&npcap_sdk_cache_path) {
      // use cached
      Ok(zip_data) => {
          eprintln!("Found cached npcap SDK");
          zip_data
      }
      // download SDK
      Err(_) => {
          eprintln!("Downloading npcap SDK");

          // download
          let mut zip_data = vec![];
          let _res = request::get(npcap_sdk_download_url, &mut zip_data)?;

          // write cache
          fs::create_dir_all(cache_dir)?;
          let mut cache = fs::File::create(npcap_sdk_cache_path)?;
          cache.write_all(&zip_data)?;

          zip_data
      }
  };

  // extract DLL
  let lib_path = if cfg!(target_arch = "aarch64") {
      "Lib/ARM64/Packet.lib"
  } else if cfg!(target_arch = "x86_64") {
      "Lib/x64/Packet.lib"
  } else if cfg!(target_arch = "x86") {
      "Lib/Packet.lib"
  } else {
      panic!("Unsupported target!")
  };
  let mut archive = ZipArchive::new(io::Cursor::new(npcap_zip))?;
  let mut npcap_lib = archive.by_name(lib_path)?;

  // write DLL
  let lib_dir = PathBuf::from(env::var("OUT_DIR")?).join("npcap_sdk");
  let lib_path = lib_dir.join("Packet.lib");
  fs::create_dir_all(&lib_dir)?;
  let mut lib_file = fs::File::create(lib_path)?;
  io::copy(&mut npcap_lib, &mut lib_file)?;

  println!(
      "cargo:rustc-link-search=native={}",
      lib_dir
          .to_str()
          .ok_or(anyhow!("{lib_dir:?} is not valid UTF-8"))?
  );

  Ok(())
}