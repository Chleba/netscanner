/// Utility for checking and reporting privileged operation requirements
use std::io;

/// Check if the current process has sufficient privileges for raw network operations
#[cfg(unix)]
pub fn has_network_privileges() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
pub fn has_network_privileges() -> bool {
    // On Windows, we can't easily check at runtime, so we assume true
    // and let the operation fail with proper error message
    true
}

/// Get a user-friendly error message for privilege-related failures
pub fn get_privilege_error_message() -> String {
    #[cfg(unix)]
    {
        let os = std::env::consts::OS;
        match os {
            "linux" => {
                format!(
                    "Insufficient privileges for network operations.\n\
                    \n\
                    This application requires raw socket access for network scanning.\n\
                    \n\
                    Please run with elevated privileges:\n\
                    - Using sudo: sudo {} [args]\n\
                    - Or set capabilities: sudo setcap cap_net_raw,cap_net_admin+eip {}\n\
                    \n\
                    Note: Setting capabilities is more secure than using sudo.",
                    std::env::current_exe()
                        .ok()
                        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                        .unwrap_or_else(|| "netscanner".to_string()),
                    std::env::current_exe()
                        .ok()
                        .and_then(|p| p.to_str().map(String::from))
                        .unwrap_or_else(|| "/path/to/netscanner".to_string())
                )
            }
            "macos" => {
                format!(
                    "Insufficient privileges for network operations.\n\
                    \n\
                    This application requires raw socket access for network scanning.\n\
                    \n\
                    Please run with elevated privileges:\n\
                    - Using sudo: sudo {} [args]\n\
                    \n\
                    On macOS, raw socket access requires root privileges.",
                    std::env::current_exe()
                        .ok()
                        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                        .unwrap_or_else(|| "netscanner".to_string())
                )
            }
            _ => {
                format!(
                    "Insufficient privileges for network operations.\n\
                    \n\
                    This application requires raw socket access for network scanning.\n\
                    Please run with elevated privileges (e.g., sudo)."
                )
            }
        }
    }

    #[cfg(windows)]
    {
        format!(
            "Insufficient privileges for network operations.\n\
            \n\
            This application requires administrative privileges for network scanning.\n\
            \n\
            Please run with elevated privileges:\n\
            - Right-click on the application and select 'Run as administrator'\n\
            - Or run from an elevated command prompt/PowerShell"
        )
    }
}

/// Check if an IO error is likely due to insufficient privileges
pub fn is_permission_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

/// Get a descriptive error message for datalink channel creation failures
pub fn get_datalink_error_message(error: &io::Error, interface_name: &str) -> String {
    if is_permission_error(error) {
        get_privilege_error_message()
    } else {
        format!(
            "Failed to create datalink channel on interface '{}'.\n\
            \n\
            Error: {}\n\
            \n\
            Possible causes:\n\
            - Interface may not exist or be down\n\
            - Insufficient privileges (see --help for privilege requirements)\n\
            - Another application may be using the interface\n\
            - Interface may not support the requested mode",
            interface_name, error
        )
    }
}
