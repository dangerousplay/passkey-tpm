//! The storage root key every credential and gate is created under (TPM-11).
//!
//! We use the standard storage root key at persistent handle 0x81000001, the slot Windows,
//! systemd and other TPM users share, so we never consume an extra persistent slot. Any
//! existing TCG-template SRK is reused (RSA-2048 is common: Windows and older systemd create
//! it); if the slot is empty we create the TCG ECC P-256 SRK. Its Name is pinned
//! when the broker provisions a user; a different Name later means the TPM was cleared.

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::structures::{
    EccPoint, Public, PublicBuilder, PublicEccParametersBuilder, SymmetricDefinitionObject,
};
use tss_esapi::Context;

use crate::error::{Error, Result};

/// TCG-reserved persistent handle for the storage root key.
pub const SRK_HANDLE: u32 = 0x8100_0001;

/// A loaded SRK and its Name.
#[derive(Debug, Clone)]
pub struct Srk {
    pub handle: KeyHandle,
    pub name: Vec<u8>,
    /// Whether secrets crossing to the TPM need session encryption (AD-013).
    pub bus: BusProtection,
}

/// Whether commands carrying secrets must use salted, parameter-encrypted sessions.
///
/// A discrete TPM sits on an LPC/SPI/I2C bus that can be sniffed or interposed, so gate
/// authValues and hmac-secret outputs must be encrypted. A firmware TPM (AMD fTPM, Intel PTT,
/// Microsoft Pluton) runs inside the SoC: there is no external bus, and salted sessions only
/// add latency (each costs a context swap through the kernel resource manager).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusProtection {
    /// No exposed bus: plain password authorisation, no parameter encryption.
    Firmware,
    /// Salted HMAC sessions with parameter encryption for every secret.
    Encrypted,
}

/// TPM_PT_MANUFACTURER values of firmware TPMs.
const FIRMWARE_VENDORS: [&[u8; 4]; 3] = [b"AMD\0", b"INTC", b"MSFT"];

/// Detects the TPM type. `PASSKEY_TPM_BUS_PROTECTION=encrypted|firmware` overrides it;
/// unknown vendors get [`BusProtection::Encrypted`].
fn detect_bus(ctx: &mut Context) -> BusProtection {
    match std::env::var("PASSKEY_TPM_BUS_PROTECTION").as_deref() {
        Ok("encrypted") => return BusProtection::Encrypted,
        Ok("firmware") => return BusProtection::Firmware,
        _ => {}
    }
    let vendor = ctx
        .get_tpm_property(tss_esapi::constants::PropertyTag::Manufacturer)
        .ok()
        .flatten()
        .map(u32::to_be_bytes);
    match vendor {
        Some(v) if FIRMWARE_VENDORS.iter().any(|f| **f == v) => BusProtection::Firmware,
        _ => BusProtection::Encrypted,
    }
}

/// TCG "TPM 2.0 Provisioning Guidance" ECC P-256 SRK template (restricted decryption key,
/// AES-128-CFB, noDA, userWithAuth, empty authPolicy, zero unique).
///
/// # Errors
/// Never in practice; propagates builder errors.
pub fn template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let params = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

fn persistent() -> Result<PersistentTpmHandle> {
    Ok(PersistentTpmHandle::new(SRK_HANDLE)?)
}

/// True if `public` is a TCG storage-root-key template (Provisioning Guidance §7.5.1):
/// a restricted decryption key with AES-128-CFB, no signing scheme, empty authPolicy,
/// `userWithAuth` and `noDA`, of type ECC P-256 or RSA-2048 (unique and exponent ignored).
fn matches_template(public: &Public) -> Result<bool> {
    let expected_attributes = template()?.object_attributes();
    let common = public.object_attributes() == expected_attributes
        && public.name_hashing_algorithm() == HashingAlgorithm::Sha256
        && public.auth_policy().is_empty();
    if !common {
        return Ok(false);
    }
    Ok(match public {
        Public::Ecc { parameters, .. } => {
            parameters.ecc_curve() == EccCurve::NistP256
                && parameters.symmetric_definition_object()
                    == SymmetricDefinitionObject::AES_128_CFB
                && parameters.ecc_scheme() == tss_esapi::structures::EccScheme::Null
        }
        Public::Rsa { parameters, .. } => {
            parameters.key_bits() == tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048
                && parameters.symmetric_definition_object()
                    == SymmetricDefinitionObject::AES_128_CFB
                && parameters.rsa_scheme() == tss_esapi::structures::RsaScheme::Null
                && matches!(parameters.exponent().value(), 0 | 65_537)
        }
        _ => false,
    })
}

/// Opens the persistent SRK if present, checking it really is an SRK.
///
/// # Errors
/// [`Error::SrkMissing`] if no object is at the handle, [`Error::NotAnSrk`] if the object
/// has another template.
pub fn open(ctx: &mut Context) -> Result<Srk> {
    let object = match ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent()?)) {
        Ok(o) => o,
        Err(_) => return Err(Error::SrkMissing),
    };
    let handle = KeyHandle::from(object);
    let (public, name, _) = ctx.read_public(handle)?;
    if !matches_template(&public)? {
        return Err(Error::NotAnSrk);
    }
    let bus = detect_bus(ctx);
    Ok(Srk {
        handle,
        name: name.value().to_vec(),
        bus,
    })
}

/// Opens the SRK and checks its Name against the pinned value (TPM-11, TPM-15).
///
/// # Errors
/// [`Error::SrkMismatch`] if the Name changed, plus the errors of [`open`].
pub fn open_pinned(ctx: &mut Context, pinned_name: &[u8]) -> Result<Srk> {
    let srk = open(ctx)?;
    if srk.name != pinned_name {
        return Err(Error::SrkMismatch);
    }
    Ok(srk)
}

/// Returns the persistent SRK, creating and persisting it in the Owner hierarchy if absent.
/// Never replaces an existing object at the handle.
///
/// # Errors
/// [`Error::NotAnSrk`] if a foreign object occupies the handle; TPM errors otherwise
/// (including when the Owner hierarchy has a password, which needs an admin to provision).
pub fn ensure(ctx: &mut Context) -> Result<Srk> {
    match open(ctx) {
        Err(Error::SrkMissing) => {}
        other => return other,
    }
    let template = template()?;
    let handle = persistent()?;
    let created = ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
    })?;
    let transient = ObjectHandle::from(created.key_handle);
    let persisted = ctx.execute_with_nullauth_session(|ctx| {
        ctx.evict_control(Provision::Owner, transient, Persistent::Persistent(handle))
    });
    ctx.flush_context(transient)?;
    persisted?;
    open(ctx)
}
