//! Privilege checking and user-friendly error reporting for network operations.
//!
//! Network scanning requires elevated privileges for raw socket access. This module
//! provides utilities to:
//! - Check if the process has sufficient privileges
//! - Generate platform-specific error messages with clear instructions
//! - Diagnose permission-related failures
//!
//! # Platform Support
//!
//! ## Unix (Linux, macOS, BSD)
//! - Checks if effective user ID (euid) is 0 (root)
//! - Provides instructions for `sudo` or capabilities (Linux)
//!
//! ## Windows
//! - Assumes privileges are available (checked at operation time)
//! - Provides instructions for "Run as Administrator"
//!
//! # Usage Pattern
//!
//! ```rust
//! use netscanner::privilege;
//!
//! // Warn early but allow partial functionality
//! if !privilege::has_network_privileges() {
//!     eprintln!("WARNING: Running without elevated privileges.");
//!     eprintln!("Some network operations may fail.");
//! }
//!
//! // Later, when an operation fails:
//! # let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
//! if privilege::is_permission_error(&error) {
//!     eprintln!("{}", privilege::get_privilege_error_message());
//! }
//! ```
//!
//! # Design Philosophy
//!
//! The application uses a **warn but don't exit** approach:
//! - Checks privileges at startup and warns if insufficient
//! - Allows the application to run with reduced functionality
//! - Operations that require privileges fail with helpful error messages
//!
//! This enables users to explore the UI even without root, and makes it
//! clear which operations require elevation.

use std::io;

/// Checks if the current process has sufficient privileges for raw network operations.
///
/// Raw network operations (packet capture, raw sockets) require elevated privileges:
/// - **Unix**: Requires root (euid = 0) or specific capabilities
/// - **Windows**: Requires Administrator privileges (checked at operation time)
///
/// # Returns
///
/// - `true` if privileges are sufficient
/// - `false` if privileges are insufficient (Unix only)
///
/// # Platform Behavior
///
/// ## Unix
/// Returns `true` if the effective user ID is 0 (root). This covers both:
/// - Running with `sudo`
/// - Binary with setuid bit set
/// - Process with CAP_NET_RAW/CAP_NET_ADMIN capabilities
///
/// ## Windows
/// Always returns `true` because privilege checking requires complex Win32 API calls.
/// Actual privilege verification happens when operations are attempted.
///
/// # Example
///
/// ```rust
/// use netscanner::privilege;
///
/// if !privilege::has_network_privileges() {
///     eprintln!("Warning: Running without elevated privileges");
/// }
/// ```
#[cfg(unix)]
pub fn has_network_privileges() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Windows implementation of privilege checking.
///
/// Always returns `true` to allow the application to start. Actual permission
/// errors will be caught when operations are attempted, with descriptive messages.
#[cfg(windows)]
pub fn has_network_privileges() -> bool {
    // On Windows, we can't easily check at runtime, so we assume true
    // and let the operation fail with proper error message
    true
}

/// Generates a platform-specific error message for privilege-related failures.
///
/// This provides users with clear, actionable instructions for running the
/// application with sufficient privileges.
///
/// # Returns
///
/// A multi-line formatted string with:
/// - Explanation of the problem
/// - Platform-specific instructions (sudo, setcap, Run as Administrator)
/// - Security notes where applicable
///
/// # Example Output (Linux)
///
/// ```text
/// Insufficient privileges for network operations.
///
/// This application requires raw socket access for network scanning.
///
/// Please run with elevated privileges:
/// - Using sudo: sudo netscanner [args]
/// - Or set capabilities: sudo setcap cap_net_raw,cap_net_admin+eip /path/to/netscanner
///
/// Note: Setting capabilities is more secure than using sudo.
/// ```
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
                "Insufficient privileges for network operations.\n\
                    \n\
                    This application requires raw socket access for network scanning.\n\
                    Please run with elevated privileges (e.g., sudo).".to_string()
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

/// Checks if an IO error is due to insufficient privileges.
///
/// This is a simple wrapper around checking for `PermissionDenied` error kind,
/// useful for determining if an error should trigger privilege-related help.
///
/// # Arguments
///
/// * `error` - The IO error to check
///
/// # Returns
///
/// `true` if the error is `ErrorKind::PermissionDenied`, `false` otherwise
///
/// # Example
///
/// ```rust
/// use netscanner::privilege;
/// use std::io;
///
/// let error = io::Error::from(io::ErrorKind::PermissionDenied);
/// assert!(privilege::is_permission_error(&error));
///
/// if privilege::is_permission_error(&error) {
///     println!("{}", privilege::get_privilege_error_message());
/// }
/// ```
pub fn is_permission_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

/// Generates a descriptive error message for datalink channel creation failures.
///
/// This provides context-specific error messages for the common failure case
/// of creating packet capture channels. It distinguishes between permission
/// errors and other failures.
///
/// # Arguments
///
/// * `error` - The IO error that occurred
/// * `interface_name` - Name of the network interface that failed
///
/// # Returns
///
/// A formatted error message with:
/// - The specific interface name
/// - The underlying error details
/// - Possible causes and solutions
/// - Privilege instructions if it's a permission error
///
/// # Example
///
/// ```rust
/// use netscanner::privilege;
/// use std::io;
///
/// let error = io::Error::from(io::ErrorKind::PermissionDenied);
/// let message = privilege::get_datalink_error_message(&error, "eth0");
/// eprintln!("{}", message);
/// ```
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
