//! Status probes. Each is bounded by [`PROBE_TIMEOUT`] and never fails: errors become the
//! corresponding "missing/unreachable/unknown" state.

use std::future::Future;
use std::time::Duration;

use passkey_tpm_uv::fprintd;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::Connection;

use crate::{Broker, PinState, Reader, Snapshot, VirtualKey};

/// Upper bound for one probe.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Broker bus name and object path (see `packaging/dbus`).
pub const BROKER_NAME: &str = "io.github.dangerousplay.PasskeyTpm1";
/// Broker object path.
pub const BROKER_PATH: &str = "/io/github/dangerousplay/PasskeyTpm1";
/// The agent's systemd user unit.
pub const AGENT_UNIT: &str = "passkey-tpm-agent.service";

async fn bounded<T>(fut: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::time::timeout(PROBE_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| Err("timed out".to_owned()))
}

/// fprintd's default device and the calling user's enrolled fingers.
pub async fn reader(system: &Connection) -> Reader {
    let name = match bounded(fprintd::device_description(system)).await {
        Ok(name) => name,
        Err(e) => return Reader::Missing(e),
    };
    let enrolled = bounded(fprintd::enrolled_fingers(system, "")).await.ok();
    Reader::Present { name, enrolled }
}

/// Whether the broker answers. `Introspect` is allowed for everyone by the broker's bus
/// policy and D-Bus-activates it, like a real request would.
pub async fn broker(system: &Connection) -> Broker {
    let call = async {
        system
            .call_method(
                Some(BROKER_NAME),
                BROKER_PATH,
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    match bounded(call).await {
        Ok(()) => Broker::Reachable,
        Err(e) => Broker::Unreachable(e),
    }
}

async fn unit_property(
    session: &Connection,
    unit: &OwnedObjectPath,
    name: &str,
) -> Result<String, String> {
    let reply = session
        .call_method(
            Some("org.freedesktop.systemd1"),
            unit.as_str(),
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.systemd1.Unit", name),
        )
        .await
        .map_err(|e| format!("Get {name}: {e}"))?;
    let value: OwnedValue = reply
        .body()
        .deserialize()
        .map_err(|e| format!("{name}: {e}"))?;
    String::try_from(value).map_err(|e| format!("{name}: {e}"))
}

/// The agent unit's state from the systemd user manager. `LoadUnit` (unlike `GetUnit`) also
/// answers for units that are installed but not loaded.
pub async fn virtual_key(session: Option<&Connection>) -> VirtualKey {
    let Some(session) = session else {
        return VirtualKey::Unknown("no session bus".to_owned());
    };
    let probe = async {
        let reply = session
            .call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.systemd1.Manager"),
                "LoadUnit",
                &(AGENT_UNIT,),
            )
            .await
            .map_err(|e| format!("LoadUnit: {e}"))?;
        let unit: OwnedObjectPath = reply
            .body()
            .deserialize()
            .map_err(|e| format!("LoadUnit reply: {e}"))?;
        let load = unit_property(session, &unit, "LoadState").await?;
        if load != "loaded" {
            return Ok(VirtualKey::Unknown(format!("{AGENT_UNIT} is {load}")));
        }
        let active = unit_property(session, &unit, "ActiveState").await?;
        Ok(if active == "active" {
            VirtualKey::Active
        } else {
            VirtualKey::Inactive(active)
        })
    };
    bounded(probe).await.unwrap_or_else(VirtualKey::Unknown)
}

/// Whether the calling user has a PIN, asked through the broker (getInfo). Runs a broker
/// request (and an audit line in its journal), so it isn't part of the periodic refresh.
pub async fn pin(system: &Connection) -> PinState {
    match bounded(async { crate::pin::is_set(system).await.map_err(|e| e.describe()) }).await {
        Ok(true) => PinState::Set,
        Ok(false) => PinState::NotSet,
        Err(e) => PinState::Unknown(e),
    }
}

/// Runs the probes concurrently. `known_pin`: reuse this PIN state instead of asking the
/// broker (periodic refreshes).
pub async fn snapshot(
    system: Option<&Connection>,
    session: Option<&Connection>,
    known_pin: Option<PinState>,
) -> Snapshot {
    let Some(system) = system else {
        let reason = "no system bus".to_owned();
        return Snapshot {
            reader: Reader::Missing(reason.clone()),
            broker: Broker::Unreachable(reason.clone()),
            key: virtual_key(session).await,
            pin: PinState::Unknown(reason),
        };
    };
    let pin_probe = async {
        match known_pin {
            Some(p) => p,
            None => pin(system).await,
        }
    };
    let (reader, broker, key, pin) = tokio::join!(
        reader(system),
        broker(system),
        virtual_key(session),
        pin_probe
    );
    Snapshot {
        reader,
        broker,
        key,
        pin,
    }
}
