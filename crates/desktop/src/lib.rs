//! Desktop integration for the passkey-tpm session programs, on zbus.
//!
//! - [`notify`]: a client for the freedesktop Notifications service (summary/body, actions,
//!   replacing and closing a notification, waiting for the user's answer).
//! - [`tray`]: a StatusNotifierItem with a `com.canonical.dbusmenu` menu, for tray hosts
//!   (KDE, Xfce, waybar…; GNOME with the AppIndicator extension).
//!
//! Both are informational UI in the user's session: same-user programs can spoof them
//! (docs/threat-model.md, "prompt spoofing"). Security decisions stay in the broker.

pub mod notify;
pub mod tray;
