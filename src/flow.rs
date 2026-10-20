// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! Orchestration of the two user journeys: registration and login.
//!
//! The other modules each solve one problem: [`crate::vault`] holds the encrypted
//! entries, [`crate::pairing`] performs the out-of-band bootstrapped key exchange,
//! [`qualia_dik::device`] handles the device identity, and [`crate::recovery`]
//! handles passphrase backups. This module chains them into the two paths a user
//! actually walks:
//!
//! ```text
//! Registration (this device is the first device of the account)
//!   generate master key → create empty vault → obtain device identity
//!   → master key into the platform key store → write vault to disk
//!
//! Login (this device receives the master key from an already logged-in device)
//!   old device: show QR code → receive request → confirm it is the user
//!               → hand over the encrypted master key
//!   new device: scan        → send request   → receive reply
//!               → master key into the platform key store → create vault
//! ```
//!
//! # Step order is a security property
//!
//! Two ordering rules hold, and callers may rely on them:
//!
//! - The master key enters the platform key store **before** the vault is written
//!   to disk. In the reverse order, a failure in between would leave an unopenable
//!   vault file behind while the user's data still appears to be there.
//! - The device identity is obtained **before** the request is sent. Otherwise the
//!   identity generated after a successful login differs from the one declared in
//!   the request, and the vault could only ever be opened by that temporary
//!   identity, which is gone with the session.
//!
//! # Platform dependencies are injected as trait parameters
//!
//! This crate has no I/O and does not touch platform APIs (see the crate docs), so
//! "store the master key in the TPM" and "read the device identity from somewhere"
//! are provided by the caller through two traits:
//!
//! | trait | implemented by | responsible for |
//! |---|---|---|
//! | [`DeviceKeys`] | the `qualia-dik` adapter | device identity, signing |
//! | [`SecureStore`] | the host side (key store / keychain) | master key persistence |
//!
//! The flow itself is pure logic and is fully unit-testable (see the tests below),
//! including every failure path, with fake implementations. The platform-specific
//! part is a thin adapter whose only job is to forward calls and make no decision:
//! a decision that leaks into the adapter is never covered by tests.
//!
//! # State after a failure
//!
//! The orchestration spans two stores (the vault file and the platform key store)
//! and there is no atomicity across them: no transaction exists between the two.
//! The order of every step is therefore chosen by what a failure leaves behind,
//! under the rule: prefer leaving something useless over leaving something that
//! cannot be opened.
//!
//! - The master key is written to [`SecureStore`] first and the vault second. If
//!   the first step fails, nothing is on disk and the user can simply retry; the
//!   vault has not been created either, so no residue is left.
//! - The reverse order (vault first) would leave a **permanently unopenable** vault
//!   file under the same failure, indistinguishable from a healthy file.
//!
//! More generally, the last fallible call in each function precedes the writes, so
//! this module currently needs no rollback logic. Changing the step order must
//! preserve that, otherwise [`SecureStore::delete_master_key`] has to be added: an
//! orphaned key in the key store is invisible to the user and cannot be deleted
//! from the UI.
//!
//! Neither [`registration`] nor [`Login`] retries automatically: failures are
//! returned as they are and the caller decides whether to start over. A silent
//! retry would turn "this platform cannot store keys", which the user must be told
//! immediately, into randomly appearing behaviour.
//!
//! This module performs no file I/O. The usual host-side layout keeps the master key in
//! the platform key store (behind [`SecureStore`]) and the vault content in a file, using
//! [`crate::vault::write_file_atomically`] and [`crate::vault::read_file`]; composing the
//! two is the caller's job.

use secrecy::{ExposeSecret as _, SecretString};

use crate::error::{Error, Result};
use crate::pairing::{self, Adoption, JoinerSession, NonceLog, PendingSession, QrPayload};
use crate::recovery::{self, KdfParams};
use crate::secret::SecretBytes;
use crate::vault::MasterKey;
use crate::vault::{Timestamp, Vault, VaultFile};
use qualia_dik::{DeviceId, DevicePublicKey, DeviceSignature};

/// Source of the device identity.
///
/// A minimal interface with exactly two methods. Generating a key inside a platform
/// key store needs `unsafe`, which this crate forbids, so the host side implements
/// this trait over the [`DeviceKeyStore`] trait of `qualia-dik` with a thin
/// forwarding adapter (see the layering notes in the crate docs).
///
/// # Host-side adapter
///
/// `qualia-dik` provides `DeviceKeyStore` (create, open and delete a device identity) and
/// `DeviceSigner` (signing). The forwarding layer looks like this:
///
/// ```text
/// impl DeviceKeys for Adapter<'_> {
///     fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey> {
///         Ok(self.store.open_or_create(label)?.public_key())
///     }
///     fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature> {
///         Ok(self.store.open(label)?.sign(message)?)
///     }
/// }
/// ```
///
/// The layer must contain no `if`: a branch there is taken only by the host side, which
/// has no unit tests in this crate.
///
/// [`DeviceKeyStore`]: https://docs.rs/qualia-dik
pub trait DeviceKeys {
    /// Returns the long-term identity of this device, creating it when absent.
    ///
    /// # Contract: idempotent
    ///
    /// Repeated calls with the same label must return the same key pair. This is a
    /// correctness requirement, not a style preference: the identity created during
    /// registration has to be retrievable on the next start, otherwise a user who
    /// restarts the app can no longer open their vault.
    ///
    /// # Contract: persisted immediately
    ///
    /// In the login flow, sending the request and receiving the reply can be far
    /// apart in time (the user walks to the other device to scan the code). An
    /// identity that lives only in memory is lost permanently if the process dies
    /// in between, and that key is the only way to open the vault. It must reach
    /// durable storage right away, even if the login never completes and the
    /// creation was wasted.
    ///
    /// # Errors
    ///
    /// Returns an error when no platform key store is available, the hardware is
    /// unavailable, or the user refuses. It must **not** silently fall back to a
    /// software key: the caller relies on the error to tell the user that the
    /// protection is weaker.
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey>;

    /// Signs the message itself with the device identity.
    ///
    /// The message is passed as is, not a digest: hashing has exactly one owner
    /// (see [`qualia_dik::device::verify`]). Implementations must not hash before
    /// signing, because the verifying side hashes again and the check would then
    /// always fail.
    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature>;
}

/// Persistence of the master key.
///
/// Storing it in a TPM is one implementation among others. When hardware protection
/// is unavailable, the host side may use the system keychain or a file protected by
/// a user passphrase; that is the host side's decision, and this module neither
/// provides nor defaults to any weaker implementation.
pub trait SecureStore {
    /// Loads the master key; returns `None` when nothing was ever stored.
    ///
    /// `Ok(None)` and `Err` mean completely different things: the former is "this
    /// device has never registered or logged in" (the normal path, where the caller
    /// guides the user to register or log in), the latter is "something was stored
    /// but cannot be read now" (the abnormal path, which may mean damaged storage
    /// or changed permissions). Conflating the two sends the user to re-register and
    /// lose the existing data for good.
    fn load_master_key(&self) -> Result<Option<MasterKey>>;

    /// Stores the master key, overwriting any existing value.
    ///
    /// This module guarantees that the key passed in has already been verified (see
    /// [`Joiner::complete`]), so implementations need no further validation.
    fn store_master_key(&mut self, key: &MasterKey) -> Result<()>;

    /// Deletes the stored master key.
    ///
    /// Used for best-effort rollback when a later step fails. A returned error must
    /// **not** be treated as fatal: a failed rollback only leaves behind a key that
    /// is of no use, while the original failure is what has to reach the user.
    /// Deleting when nothing was ever stored must succeed, not fail.
    fn delete_master_key(&mut self) -> Result<()>;

    /// Reports whether this implementation keeps the master key in non-exportable
    /// hardware.
    ///
    /// Callers use it to tell the user how strong the protection is. It is a claim
    /// by the implementation about its own capabilities, not a fact this module can
    /// verify, so it must answer truthfully and never return `true` to make the UI
    /// look good.
    fn is_hardware_backed(&self) -> bool;
}

/// The result of a successful registration.
#[derive(Debug)]
pub struct Registered {
    /// Public key of this device's identity.
    device: DevicePublicKey,
    /// The newly created empty vault, together with its master key.
    vault: VaultFile,
    /// Whether the platform store claims to keep the master key in non-exportable
    /// hardware.
    hardware_backed: bool,
}

impl Registered {
    /// The identity of this device.
    #[must_use]
    pub const fn device(&self) -> &DevicePublicKey {
        &self.device
    }

    /// Identifier of this device's identity.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device.device_id()
    }

    /// The newly created vault.
    #[must_use]
    pub const fn vault(&self) -> &VaultFile {
        &self.vault
    }

    /// Mutable reference to the new vault, for writing the first entries.
    pub const fn vault_mut(&mut self) -> &mut VaultFile {
        &mut self.vault
    }

    /// Whether the master key is protected by hardware.
    #[must_use]
    pub const fn is_hardware_backed(&self) -> bool {
        self.hardware_backed
    }

    /// Consumes the result and returns the vault.
    #[must_use]
    pub fn into_vault(self) -> VaultFile {
        self.vault
    }

    /// Consumes the result and returns the master key and the vault.
    #[must_use]
    pub fn into_parts(self) -> (MasterKey, Vault) {
        self.vault.into_parts()
    }
}

/// Registers a new device: generates the master key, creates an empty vault,
/// obtains the device identity, and persists the master key.
///
/// The returned vault is **not yet written to disk**: the caller normally writes
/// the first entries into it and then calls [`crate::vault::VaultFile::serialize`].
/// Writing the empty vault once and again after the entries would make the final
/// content depend on which write succeeded, and the caller cannot tell.
///
/// # Parameters
///
/// - `label`: label of the device identity in the platform key store. Use a
///   **stable** value (identical on every start of the same device), otherwise
///   [`DeviceKeys::get_or_create`] creates the same identity more than once.
/// - `keys` / `store`: see the two trait documents.
///
/// # Step order
///
/// 1. generate the master key;
/// 2. obtain the device identity;
/// 3. ask the store whether it is hardware-backed;
/// 4. store the master key ([`SecureStore::store_master_key`]).
///
/// Step 4 is the last fallible step: steps 1 to 3 above all precede it, so there is
/// no window where the master key is stored and a later step fails, and this
/// function needs no rollback. Changing this order requires adding a
/// [`SecureStore::delete_master_key`] rollback, otherwise an orphaned key is left in
/// the key store that the user cannot see and cannot delete from the UI.
///
/// # Errors
///
/// Returns the corresponding error when creating the device identity fails (the
/// platform is unsupported, the hardware is unavailable) or when storing the master
/// key fails; **no vault is created in that case**.
pub fn registration(
    keys: &mut dyn DeviceKeys,
    store: &mut dyn SecureStore,
    label: &str,
) -> Result<Registered> {
    let master = MasterKey::generate()?;

    let device = keys.get_or_create(label)?;

    let hardware_backed = store.is_hardware_backed();

    store.store_master_key(&master)?;

    Ok(Registered {
        device,
        vault: VaultFile::with_master_key(master),
        hardware_backed,
    })
}

/// The initiating side of a login: a device that is **already logged in** and holds
/// the master key.
///
/// It shows the QR code, receives the request, and hands over the encrypted master
/// key.
///
/// # One instance per login
///
/// This type holds one-time ephemeral keys (see the session binding rules in
/// [`crate::pairing`]), so a single `Login` cannot serve two logins: `authorize`
/// consumes the pending session and a second call always fails. Call [`Login::new`]
/// to start over after the user cancels.
pub struct Login {
    /// QR payload of this login.
    ///
    /// Stored separately rather than read from `pending`, because
    /// `PendingSession::accept` takes `self` and moves it out, while the payload
    /// must remain accessible after authorization (it is logged and may be shown
    /// again). [`QrPayload`] is `Copy` and is public material by design, so the
    /// extra copy raises no confidentiality concern.
    payload: QrPayload,
    /// Session awaiting the request of the other side; `None` after a successful
    /// `authorize`.
    pending: Option<PendingSession>,
    /// The accepted session, set after a successful `authorize`.
    adoption: Option<Adoption>,
    /// Session identifiers already used, for replay rejection.
    used: NonceLog,
}

impl core::fmt::Debug for Login {
    /// Prints state only, never session contents (they hold one-time ephemeral
    /// keys).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Login")
            .field("capabilities", &self.payload.capabilities())
            .field("outstanding", &self.pending.is_some())
            .field("authorized", &self.adoption.is_some())
            .field("used_sessions", &self.used.len())
            .finish_non_exhaustive()
    }
}

impl Login {
    /// Starts a login.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the randomness source is
    /// unavailable. Failing is mandatory here: predictable ephemeral keys would
    /// leave the handshake with no confidentiality at all.
    pub fn new() -> Result<Self> {
        let (payload, pending) = pairing::begin()?;
        Ok(Self {
            payload,
            pending: Some(pending),
            adoption: None,
            used: NonceLog::new(),
        })
    }

    /// Returns the content to be displayed as a QR code.
    ///
    /// The caller renders it. It must be displayed on a trusted screen: whoever
    /// sees it can complete a login with this device. That is intentional, the first
    /// key transfer is protected by the out-of-band channel.
    #[must_use]
    pub const fn payload(&self) -> &QrPayload {
        &self.payload
    }

    /// Accepts the request of a new device and hands the master key over encrypted.
    ///
    /// # Human confirmation before returning
    ///
    /// The `msg1` received here only proves that the other side claims a device
    /// identity; it does not prove who they are. After the QR code has been scanned
    /// and before calling this function, the caller (the UI) must explicitly let the
    /// user confirm that this login is theirs. Skipping that step hands the master
    /// key to anyone who scanned the QR code.
    ///
    /// This module cannot enforce it: it has no UI. It can only shape the API so
    /// that the call requires an explicit action, which makes a forgotten
    /// confirmation visible in review.
    ///
    /// # Replay
    ///
    /// Before accepting, the session is checked against the ones already used in
    /// this login; a used session returns [`Error::PairingAuthenticationFailed`].
    /// The check covers only sessions of the current process: replay protection
    /// across restarts requires the caller to persist [`Login::used_sessions`] (see
    /// [`crate::pairing::NonceLog`]).
    ///
    /// # Errors
    ///
    /// Returns the corresponding error when the request is malformed, cannot be
    /// opened for this session (it was not addressed to this login, or it was
    /// modified), or the session is replayed. None of them returns a partial result.
    pub fn authorize(&mut self, msg1: &[u8], master: &MasterKey) -> Result<Vec<u8>> {
        let pending = self
            .pending
            .take()
            .ok_or(Error::PairingAuthenticationFailed)?;
        let adoption = pending.accept(msg1, master)?;

        if !self.used.record(*adoption.session_id()) {
            return Err(Error::PairingAuthenticationFailed);
        }

        let reply = adoption.reply().to_vec();
        self.adoption = Some(adoption);
        Ok(reply)
    }

    /// Session identifier of this login, available after a successful `authorize`.
    ///
    /// The caller should persist it together with the time of this login, so that
    /// replay protection can be restored on the next start with
    /// [`Login::with_used_sessions`].
    #[must_use]
    pub fn session_id(&self) -> Option<&[u8; pairing::SESSION_ID_LEN]> {
        self.adoption.as_ref().map(Adoption::session_id)
    }

    /// Session identifiers already used.
    #[must_use]
    pub const fn used_sessions(&self) -> &NonceLog {
        &self.used
    }

    /// Restores the used session identifiers recorded by a previous run.
    #[must_use]
    pub fn with_used_sessions(mut self, used: NonceLog) -> Self {
        self.used = used;
        self
    }

    /// Device identity declared by the other side (the new device), available after
    /// a successful `authorize`.
    ///
    /// The caller should record it as evidence that this new device was authorized.
    #[must_use]
    pub fn joiner_device(&self) -> Option<DeviceId> {
        self.adoption
            .as_ref()
            .and_then(|a| DevicePublicKey::from_sec1_bytes(a.joiner_identity()).ok())
            .map(|key| key.device_id())
    }
}

/// The receiving side of a login: a new device that does **not** hold the master key
/// yet.
///
/// # One instance per login
///
/// Like [`Login`], this type holds one-time ephemeral keys. After `request`,
/// [`Joiner::complete`] must be called on the **same instance**; a new instance
/// cannot finish a previous login because its ephemeral keys differ (see the session
/// binding rules in [`crate::pairing`]).
///
/// # `session` is an `Option`
///
/// [`Joiner::complete`] takes `&self` rather than `self`, so the host side can keep
/// this type in a shared container such as `Arc<Mutex<..>>`, as the bindings layer
/// and the UI require shared references. The session itself is still one-time:
/// `complete` takes it with [`Option::take`] and a second call returns
/// [`Error::PairingAuthenticationFailed`] instead of replaying.
///
/// As in [`Login`] (`Option<PendingSession>` plus `take`), single use is a property
/// of the type rather than a boolean flag the caller has to maintain.
/// `Option::take` needs `&mut`, hence the internal [`std::sync::Mutex`] that
/// provides interior mutability.
pub struct Joiner {
    /// Ephemeral session of this login; `None` once `complete` has taken it.
    session: std::sync::Mutex<Option<JoinerSession>>,
    /// Device identity label, used for signing in `complete`.
    label: String,
    /// Session identifier once the request has been sent.
    session_id: Option<[u8; pairing::SESSION_ID_LEN]>,
    /// The message emitted by `request`, for diagnostics and test comparison.
    request: Vec<u8>,
}

impl core::fmt::Debug for Joiner {
    /// Prints no session contents (they hold one-time ephemeral keys).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Joiner")
            .field("label", &self.label)
            .field("requested", &self.session_id.is_some())
            .finish_non_exhaustive()
    }
}

impl Joiner {
    /// Starts a login from a scanned QR code.
    ///
    /// The QR code must come from the out-of-band channel (scanned in person).
    /// Handling `payload` as an ordinary message received over the network loses
    /// that protection: a man in the middle can substitute their own public key and
    /// obtain the master key without either device noticing.
    ///
    /// # Errors
    ///
    /// Returns the corresponding error when the payload is malformed, its version is
    /// unsupported, or its ephemeral public key is not on the curve.
    pub fn new(payload: &QrPayload, label: &str) -> Result<Self> {
        Ok(Self {
            session: std::sync::Mutex::new(Some(pairing::join(payload)?)),
            label: label.to_owned(),
            session_id: None,
            request: Vec::new(),
        })
    }

    /// Starts a login from the QR payload in text form.
    ///
    /// For callers whose scanner yields a string rather than bytes.
    pub fn from_base32(text: &str, label: &str) -> Result<Self> {
        Self::new(&QrPayload::from_base32(text)?, label)
    }

    /// Returns the request message to send to the old device.
    ///
    /// # Errors
    ///
    /// Returns the corresponding error when the device identity cannot be obtained
    /// or signing fails. **Repeated calls return a copy of the same message** and do
    /// not sign again: a fresh message would carry a new session identifier, so the
    /// old device would not recognize it as the same login.
    pub fn request(&mut self, keys: &mut dyn DeviceKeys) -> Result<Vec<u8>> {
        if self.request.is_empty() {
            let identity = keys.get_or_create(&self.label)?;
            let (message, session_id) = {
                let session = self.session_guard();
                let session = session.as_ref().ok_or(Error::PairingAuthenticationFailed)?;
                session.request(identity.as_sec1_bytes())?
            };
            self.request = message;
            self.session_id = Some(session_id);
        }
        Ok(self.request.clone())
    }

    /// Session identifier of this login, available once the request has been sent.
    #[must_use]
    pub const fn session_id(&self) -> Option<&[u8; pairing::SESSION_ID_LEN]> {
        self.session_id.as_ref()
    }

    /// Completes the login with the reply of the old device and writes the master
    /// key into the platform store.
    ///
    /// On success the caller should write an empty vault file and later fetch the
    /// content with [`crate::vault::read_file`] or through synchronization. The
    /// login itself carries no entries: the master key and the entries travel
    /// separately.
    ///
    /// # Errors
    ///
    /// Returns the corresponding error when the reply is malformed, authentication
    /// fails (it was not addressed to this session, it was modified, or it comes
    /// from a forged old device), or storing the master key fails.
    ///
    /// **A failed store does not lose the master key**: it disappears together with
    /// the return value, so no intermediate state where the caller holds a key that
    /// was not stored can mislead it. The caller should send the user through the
    /// login again.
    ///
    /// # Single use
    ///
    /// The session is taken with [`Option::take`], so a repeated call returns
    /// [`Error::PairingAuthenticationFailed`], the same error as for a forged reply,
    /// because both are handled the same way (run the login again). It deliberately
    /// does not report "already used": that would tell an attacker their replay was
    /// recognized.
    ///
    /// The receiver is `&self` rather than `self` so that callers can keep this type
    /// in a shared container such as `Arc<Mutex<..>>`, as the bindings layer and the
    /// UI require shared references. Single use is enforced by the internal
    /// `Option`, not by ownership.
    pub fn complete(
        &self,
        msg2: &[u8],
        keys: &mut dyn DeviceKeys,
        store: &mut dyn SecureStore,
    ) -> Result<MasterKey> {
        let identity = keys.get_or_create(&self.label)?;
        let session = self
            .session_guard()
            .take()
            .ok_or(Error::PairingAuthenticationFailed)?;
        let master = session.open(msg2, identity.as_sec1_bytes())?;
        store.store_master_key(&master)?;
        Ok(master)
    }

    /// Public key of the identity this device uses in this login.
    ///
    /// Returns `None` once [`Joiner::complete`] has taken the session. The host side
    /// shows it to the user for confirmation before completion, so the user can see
    /// whether the device requesting the login is the expected one.
    #[must_use]
    pub fn identity(&self) -> Option<[u8; pairing::PUBLIC_KEY_LEN]> {
        self.session_guard()
            .as_ref()
            .map(|session| *session.public_key())
    }

    /// Borrows the inner session, ignoring poisoning.
    ///
    /// Poisoning means a thread panicked while holding the lock. This lock only
    /// guards taking an `Option` and has no half-updated intermediate state, so
    /// recovering is preferable to a login flow that fails forever.
    fn session_guard(&self) -> std::sync::MutexGuard<'_, Option<JoinerSession>> {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Hands the master key back to the other devices of the account.
///
/// The recovery key serves two situations: all devices are lost, or the user moves
/// to a new device. This function only produces the file content; where it is
/// stored and how the user obtains it is up to the caller.
///
/// # Parameters
///
/// - `passphrase`: user passphrase. An empty passphrase is rejected by
///   [`crate::recovery::export`]: it would waste the whole cost of Argon2id.
/// - `params`: KDF parameters; `None` uses [`KdfParams::recommended`].
///
/// # Errors
///
/// Returns the corresponding error when the passphrase is empty, the parameters are
/// out of range, or the randomness source is unavailable.
pub fn export_recovery_key(
    master: &MasterKey,
    passphrase: &SecretString,
    params: Option<KdfParams>,
) -> Result<Vec<u8>> {
    recovery::export(
        master,
        passphrase,
        &params.unwrap_or_else(KdfParams::recommended),
    )
}

/// Recovers the master key from a recovery file and writes it into the platform
/// store.
///
/// Both steps happen here: a failure between recovering the key and storing it would
/// leave the dangerous state where the user sees a successful recovery but the key
/// is gone after a restart.
///
/// # Errors
///
/// Returns the corresponding error when the file structure is wrong, the passphrase
/// is wrong, or the platform store write fails. **A wrong passphrase and a tampered
/// file return the same error** (see the threat model in [`crate::recovery`]):
/// distinguishing them would give an attacker an oracle through the error type.
pub fn import_recovery_key(
    file: &[u8],
    passphrase: &SecretString,
    store: &mut dyn SecureStore,
) -> Result<MasterKey> {
    let master = recovery::import(file, passphrase)?;
    store.store_master_key(&master)?;
    Ok(master)
}

/// What a portable vault file turned out to be, once it has been opened.
///
/// The two shapes are kept apart rather than folded into "a vault or an error": the old
/// key-only file is a legitimate file, and the reason it cannot restore an account on its own is
/// a **property of the file**, not a failure. The caller decides what to say from this.
#[derive(Debug)]
pub enum PortableRestore {
    /// The master key was written to the platform store and the vault the file carried opened.
    Vault(crate::vault::VaultFile),
    /// The file is an old key-only recovery file: it carries the master key but no entries.
    ///
    /// Nothing was written: the key is only useful against a vault this device already has, and
    /// replacing a working key with one that opens nothing is worse than doing nothing. A caller
    /// that has a local vault may retry with [`import_recovery_key`] on the file's own bytes.
    KeyOnly,
}

/// Restores an account from a **portable vault file**: the two `.q2fa` containers.
///
/// # What it does, in this order
///
/// 1. Split the container into its parts (no cryptography yet).
/// 2. An old key-only file is reported as [`PortableRestore::KeyOnly`] and **nothing is written**.
/// 3. Recover the master key: the plain container carries it; the encrypted one is opened with
///    `passphrase` by [`crate::recovery`].
/// 4. **Write the master key to the store**, because the vault can only be opened by reading it
///    back from there.
/// 5. Parse the vault the container carries.
///
/// # Why the key is written before the vault is parsed
///
/// There is no transaction across the two stores. The order therefore follows "what is left if
/// this fails": writing the key first means a failure leaves a vault that was never touched, and
/// step 5 puts the previous key back (or removes the one just written) so the device does not end
/// up on a key that opens nothing. The opposite order would leave a vault written under a key that
/// is not stored anywhere.
///
/// # Errors
///
/// - [`crate::Error::PortableVaultFileWithoutKey`]: the file is a bare vault file.
/// - [`crate::Error::PortablePasswordRequired`]: the encrypted container was opened without a
///   passphrase.
/// - [`crate::Error::PortableBadMagic`], [`crate::Error::PortableUnsupportedVersion`],
///   [`crate::Error::PortableTruncated`], [`crate::Error::PortableLengthMismatch`],
///   [`crate::Error::PortableTooLarge`]: the container is malformed.
/// - [`crate::Error::RecoveryAuthenticationFailed`]: the passphrase is wrong, or the encrypted
///   part was modified. The two are deliberately indistinguishable.
/// - [`crate::Error::VaultDecryptionFailed`]: the master key recovered from the file does not
///   open the vault the file carries. **The previous key has been put back.**
pub fn open_portable(
    file: &[u8],
    passphrase: &SecretString,
    store: &mut dyn SecureStore,
) -> Result<PortableRestore> {
    use crate::portable::{PortableFile, parse};

    let parsed = parse(file)?;
    let (master, vault_bytes) = match parsed {
        PortableFile::KeyOnly { .. } => return Ok(PortableRestore::KeyOnly),
        PortableFile::PlainVault { master_key, vault } => {
            (MasterKey::from_bytes(master_key)?, vault)
        }
        PortableFile::EncryptedVault { recovery, vault } => {
            if passphrase.expose_secret().is_empty() {
                return Err(Error::PortablePasswordRequired);
            }
            (crate::recovery::import(&recovery, passphrase)?, vault)
        }
    };

    let previous = store.load_master_key()?;
    store.store_master_key(&master)?;

    match crate::vault::VaultFile::parse(master, &vault_bytes) {
        Ok(opened) => Ok(PortableRestore::Vault(opened)),
        Err(error) => {
            // Put the device back on the key it had. A failure of the rollback itself must not
            // replace the real diagnosis, which is why its result is deliberately dropped.
            let _ = match previous {
                Some(previous) => store.store_master_key(&previous),
                None => store.delete_master_key(),
            };
            Err(error)
        }
    }
}

/// Opens an existing vault, taking the master key from the platform store.
///
/// The result is decidable: [`Error::DeviceNotRegistered`] means this device never
/// logged in (guide the user to register or log in), and any other error means it
/// did log in but the vault cannot be opened (the data may be damaged, so do **not**
/// suggest re-registering).
///
/// # Errors
///
/// Returns [`Error::DeviceNotRegistered`] when nothing is stored;
/// [`Error::VaultDecryptionFailed`] when `data` is not the content of this vault or
/// the master key does not match.
///
/// # Empty vaults also detect a wrong master key
///
/// Format version 2 puts a master key check value at the end of the file, so **a
/// file with no entries is decided as well**: a wrong stored master key returns
/// [`Error::VaultDecryptionFailed`] instead of surfacing only when the user adds the
/// first entry.
///
/// **Old version 1 files still cannot be decided**: such a file holds nothing to
/// decide on and parsing skips the check value. Use the challenge-response of
/// [`crate::auth`] when the key needs authoritative confirmation; it does not depend
/// on file content.
pub fn open_vault(store: &dyn SecureStore, data: &[u8]) -> Result<VaultFile> {
    let master = store.load_master_key()?.ok_or(Error::DeviceNotRegistered)?;
    VaultFile::parse(master, data)
}

/// Converts [SecretBytes] into a master key, for host-side code implementing
/// [`SecureStore`].
///
/// Both restore paths, [`crate::pairing::master_key_from_storage`] and
/// [`crate::recovery`], are unified here: the host side only has to remember "bytes
/// go in, this function takes them out" and needs no knowledge of where validation
/// happens.
///
/// # Errors
///
/// Returns [`Error::MasterKeyWrongLength`] when the length is not
/// [`crate::vault::MASTER_KEY_LEN`].
pub fn master_key_from_bytes(bytes: SecretBytes) -> Result<MasterKey> {
    MasterKey::from_bytes(bytes)
}

/// Returns the storable byte form of a master key, for host-side code implementing
/// [`SecureStore`].
///
/// The counterpart of [`master_key_from_bytes`]. [`SecretBytes`] is wiped on drop.
#[must_use]
pub fn master_key_to_bytes(key: &MasterKey) -> SecretBytes {
    crate::vault::master_key_to_bytes(key)
}

/// Creates an empty vault file from a recovery or login result.
///
/// Login and recovery deliver the master key only, never entries. The caller needs
/// an empty but correctly formatted vault file to hold the entries that are
/// synchronized later; hand-writing the file bytes would bypass format validation.
#[must_use]
pub fn empty_vault(master: MasterKey) -> VaultFile {
    VaultFile::with_master_key(master)
}

/// The "now" recorded as an entry insertion time.
///
/// This crate does not read the clock (see the crate docs), so time is always passed
/// in by the caller. The alias makes the orchestration signatures read as "needs a
/// time" rather than "needs a `u64`".
pub type Now = Timestamp;

/// Validates a current timestamp supplied by the caller for entry insertion.
///
/// This crate cannot read the clock, so the check **rejects obviously invalid
/// values**: `0` usually means the caller forgot to pass one, and it would become
/// the smallest timestamp in the vault, making later time-ordered merge logic
/// produce stable but wrong results.
///
/// # Errors
///
/// Returns [`Error::TimestampZero`] when `now` is `0`.
pub const fn check_now(now: Now) -> Result<Now> {
    if now == 0 {
        return Err(Error::TimestampZero);
    }
    Ok(now)
}

/// Explicitly exposes the length of a [`SecretString`] for logging and diagnostics.
///
/// The passphrase itself must never be printed, but its length is the only useful
/// and non-leaking fact when diagnosing a failed import. Making it a function keeps
/// "no passphrase leaks here" visible in review instead of a guess from reading a
/// `format!`.
#[must_use]
pub fn passphrase_len(passphrase: &SecretString) -> usize {
    passphrase.expose_secret().chars().count()
}

/// Lets `&mut T` be used as [`DeviceKeys`] as well.
///
/// Callers do not need a forwarding layer to lend an implementation to this module:
/// `registration` takes `&mut dyn DeviceKeys`, and both `&mut adapter` and
/// `&mut *adapter` compile.
impl<T: DeviceKeys + ?Sized> DeviceKeys for &mut T {
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey> {
        (**self).get_or_create(label)
    }

    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature> {
        (**self).sign(label, message)
    }
}

/// Lets `&mut T` be used as [`SecureStore`] as well.
impl<T: SecureStore + ?Sized> SecureStore for &mut T {
    fn load_master_key(&self) -> Result<Option<MasterKey>> {
        (**self).load_master_key()
    }

    fn store_master_key(&mut self, key: &MasterKey) -> Result<()> {
        (**self).store_master_key(key)
    }

    fn delete_master_key(&mut self) -> Result<()> {
        (**self).delete_master_key()
    }

    fn is_hardware_backed(&self) -> bool {
        (**self).is_hardware_backed()
    }
}

/// Checks that a device identity is the one this device declared.
///
/// For callers to compare against an identity claimed by the other side. **This only
/// compares identifiers and proves nothing**: who a public key belongs to is answered
/// by the authentication tag of the pairing protocol (see [`crate::pairing`]), not by
/// comparing bytes.
///
/// # Errors
///
/// Returns [`Error::DeviceIdentityMismatch`] when the two differ.
pub fn expect_device(
    actual: &DevicePublicKey,
    claimed: &[u8; pairing::PUBLIC_KEY_LEN],
) -> Result<()> {
    if actual.as_sec1_bytes() != claimed {
        return Err(Error::DeviceIdentityMismatch);
    }
    Ok(())
}

/// Checks that a message was really signed by a device identity.
///
/// The verification itself lives in `qualia_dik::device`; this wrapper translates a
/// failure into this crate's error type ([`Error::Device`]). Callers get a single
/// entry point instead of each of them calling `qualia_dik::device::verify`, and
/// downstream layers (FFI, UI) receive this crate's error enum.
///
/// # Errors
///
/// Returns [`Error::Device`] when the signature does not match or is malformed; the
/// inner error is `DeviceSignatureInvalid` from the device identity library.
pub fn verify_device(
    public_key: &DevicePublicKey,
    message: &[u8],
    signature: &DeviceSignature,
) -> Result<()> {
    Ok(qualia_dik::device::verify(public_key, message, signature)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer as _};
    use qualia_dik::device::SIGNATURE_LEN;
    use std::collections::HashMap;

    /// An in-memory [`DeviceKeys`] implementation that keeps the orchestration logic
    /// away from the platform.
    ///
    /// It signs with a plain software key and never claims hardware backing.
    struct FakeKeys {
        /// Identities created so far, keyed by label.
        keys: HashMap<String, SigningKey>,
        /// Number of creations, for idempotency checks.
        creates: usize,
    }

    impl FakeKeys {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
                creates: 0,
            }
        }
    }

    impl DeviceKeys for FakeKeys {
        fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey> {
            if !self.keys.contains_key(label) {
                let scalar = label.bytes().fold(1_u8, u8::wrapping_add).max(1);
                let mut seed = [0_u8; 32];
                seed[31] = scalar;
                self.keys.insert(
                    label.to_owned(),
                    SigningKey::from_slice(&seed).expect("the test scalar must be valid"),
                );
                self.creates += 1;
            }
            let key = &self.keys[label];
            let point = key.verifying_key().to_sec1_point(false);
            Ok(DevicePublicKey::from_sec1_bytes(point.as_bytes())?)
        }

        fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature> {
            let key = self.keys.get(label).ok_or(Error::DeviceKeyMissing)?;
            let signature: p256::ecdsa::Signature = key.sign(message);
            Ok(DeviceSignature::from_bytes(&signature.to_bytes())?)
        }
    }

    /// In-memory [`SecureStore`]. `hardware` is configurable so that the forwarding
    /// of that claim can be verified.
    #[derive(Default)]
    struct FakeStore {
        master: Option<MasterKey>,
        hardware: bool,
        /// When set, makes `store_master_key` fail; used for failure paths.
        fail_store: bool,
        deletes: usize,
    }

    impl SecureStore for FakeStore {
        fn load_master_key(&self) -> Result<Option<MasterKey>> {
            Ok(self.master.as_ref().map(|k| {
                MasterKey::from_bytes(master_key_to_bytes(k))
                    .expect("the length is guaranteed by construction")
            }))
        }

        fn store_master_key(&mut self, key: &MasterKey) -> Result<()> {
            if self.fail_store {
                return Err(Error::SecureStoreWriteFailed {
                    reason: "failure injected by the test",
                });
            }
            self.master = Some(
                MasterKey::from_bytes(master_key_to_bytes(key))
                    .expect("the length is guaranteed by construction"),
            );
            Ok(())
        }

        fn delete_master_key(&mut self) -> Result<()> {
            self.deletes += 1;
            self.master = None;
            Ok(())
        }

        fn is_hardware_backed(&self) -> bool {
            self.hardware
        }
    }

    const LABEL: &str = "qualia2fa-device";

    fn registered() -> (FakeKeys, FakeStore, Registered) {
        let mut keys = FakeKeys::new();
        let mut store = FakeStore::default();
        let result =
            registration(&mut keys, &mut store, LABEL).expect("registration should succeed");
        (keys, store, result)
    }

    /// Registration produces three usable things: the master key is stored, the
    /// vault opens, and the identity can be retrieved.
    #[test]
    fn registration_produces_a_usable_device() {
        let (keys, store, result) = registered();
        assert!(
            store.master.is_some(),
            "the master key must be in the platform store"
        );
        assert!(
            keys.keys.contains_key(LABEL),
            "the device identity must have been created and be retrievable by the same label"
        );
        assert!(!result.is_hardware_backed());

        let data = result
            .vault
            .serialize()
            .expect("serialization should succeed");
        let opened =
            open_vault(&store, &data).expect("the stored master key should open the vault");
        assert!(opened.vault().is_empty());
        assert_eq!(
            opened.master_key().expose(),
            result.vault.master_key().expose()
        );
    }

    /// Two registrations produce **different** master keys; otherwise a second
    /// device would overwrite the account of the first.
    #[test]
    fn each_registration_generates_a_fresh_master_key() {
        let (_k1, _s1, first) = registered();
        let (_k2, _s2, second) = registered();
        assert_ne!(
            first.vault.master_key().expose(),
            second.vault.master_key().expose()
        );
    }

    /// Repeated `get_or_create` calls with the same label create no new identity.
    ///
    /// This is necessary and sufficient for opening the vault after an app restart.
    #[test]
    fn device_identity_is_stable_across_calls() {
        let mut keys = FakeKeys::new();
        let first = keys
            .get_or_create(LABEL)
            .expect("the first creation should succeed");
        let second = keys
            .get_or_create(LABEL)
            .expect("the second retrieval should succeed");
        assert_eq!(first.as_sec1_bytes(), second.as_sec1_bytes());
        assert_eq!(keys.creates, 1, "must not create a second identity");
    }

    /// A failed master key write creates **no** vault.
    ///
    /// A file that cannot be opened is worse than no file at all, because the user
    /// cannot tell it from a healthy one.
    #[test]
    fn registration_does_not_create_a_vault_when_storage_fails() {
        let mut keys = FakeKeys::new();
        let mut store = FakeStore {
            fail_store: true,
            ..FakeStore::default()
        };
        let error = registration(&mut keys, &mut store, LABEL).expect_err("should fail");
        assert!(
            matches!(error, Error::SecureStoreWriteFailed { .. }),
            "the error should be a write failure, got {error:?}"
        );
        assert!(store.master.is_none());
    }

    /// Opening a vault on a device that never logged in reports a **distinguishable**
    /// error.
    ///
    /// Sharing that error with "key mismatch" would leave the UI unable to tell
    /// whether to guide the user to log in or to warn about damaged data; the latter
    /// leads to re-registration and permanent loss of the existing data.
    #[test]
    fn opening_without_a_stored_key_reports_not_registered() {
        let store = FakeStore::default();
        let (_k, _s, result) = registered();
        let data = result
            .vault
            .serialize()
            .expect("serialization should succeed");
        let error = open_vault(&store, &data).expect_err("must fail without a stored master key");
        assert!(matches!(error, Error::DeviceNotRegistered), "got {error:?}");
    }

    /// **An empty vault also detects a wrong master key.**
    ///
    /// Format version 2 appends a master key check value, so a file with no entries
    /// is decided as well: an empty vault opened with the wrong key must be rejected.
    ///
    /// The "other device" uses **its own** master key rather than a borrowed random
    /// value, which would hide the real situation of two devices that each registered
    /// and each hold a valid master key.
    #[test]
    fn an_empty_vault_rejects_a_wrong_key() {
        let (_k, _s, result) = registered();
        assert!(
            result.vault.vault().is_empty(),
            "precondition: this vault really is empty"
        );
        let data = result
            .vault
            .serialize()
            .expect("serialization should succeed");

        let (_k2, store, device2) = registered();
        assert_ne!(
            device2.vault().master_key().expose(),
            result.vault.master_key().expose(),
            "the two devices must have different master keys, or this test proves nothing"
        );

        let error =
            open_vault(&store, &data).expect_err("an empty vault must reject the wrong key");
        assert!(
            matches!(error, Error::VaultDecryptionFailed),
            "got {error:?}"
        );
    }

    /// A vault with entries rejects the wrong key as well.
    ///
    /// This is the other half of the previous test; the two cover **different**
    /// failure points: an empty file relies on the trailing check value, a file with
    /// entries on the AEAD tag of a record (the check value is there too, but the
    /// record is reached first).
    #[test]
    fn a_vault_with_entries_rejects_the_wrong_key() {
        use crate::uri;
        use crate::vault::{Timestamp, entry_from_parsed_uri};

        let (_k, _s, mut result) = registered();
        let parsed = uri::parse("otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME")
            .expect("the URI should be valid");
        const NOW: Timestamp = 1_700_000_000;
        let entry = entry_from_parsed_uri(parsed, NOW).expect("the entry should be built");
        result
            .vault_mut()
            .vault_mut()
            .insert(entry)
            .expect("the insert should succeed");
        let data = result
            .vault
            .serialize()
            .expect("serialization should succeed");

        let (_k2, store, _device2) = registered();
        let error =
            open_vault(&store, &data).expect_err("a vault with entries must reject the wrong key");
        assert!(
            matches!(error, Error::VaultDecryptionFailed),
            "got {error:?}"
        );
    }

    /// A full login round trip: the master key the new device receives must be
    /// exactly the one of the old device, and a login can be completed only once.
    ///
    /// `Joiner::complete` takes `&self` (so callers can keep it in a shared container)
    /// and the internal `Option` enforces single use. A second call must fail with the
    /// **same error as a forged reply**: reporting "already used" separately would
    /// tell an attacker their replay was recognized.
    #[test]
    fn a_login_can_only_be_completed_once() {
        let (_old_keys, _old_store, account) = registered();
        let master = account.vault.master_key();

        let mut login = Login::new().expect("the login should start");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner =
            Joiner::new(&payload, "new-device").expect("the joiner session should start");
        let request = joiner
            .request(&mut keys)
            .expect("the request should be produced");
        let reply = login
            .authorize(&request, master)
            .expect("authorization should succeed");

        let mut store = FakeStore::default();
        joiner
            .complete(&reply, &mut keys, &mut store)
            .expect("the first call should succeed");

        let error = joiner
            .complete(&reply, &mut keys, &mut store)
            .expect_err("the second call must fail");
        assert!(
            matches!(error, Error::PairingAuthenticationFailed),
            "must report the same error as a forged reply, got {error:?}"
        );

        assert!(joiner.identity().is_none());
    }

    /// Comparing only "no error" is not enough: an implementation that replaces the
    /// master key with a fresh random value reports no error either, and the user only
    /// finds out at synchronization time that no entry matches.
    #[test]
    fn login_transfers_the_exact_master_key() {
        let (_old_keys, old_store, account) = registered();
        let master = account.vault.master_key();

        let mut login = Login::new().expect("the login should start");
        let payload = login.payload().clone();

        let mut joiner_keys = FakeKeys::new();
        let mut joiner =
            Joiner::new(&payload, "new-device").expect("the joiner session should start");
        let request = joiner
            .request(&mut joiner_keys)
            .expect("the request should be produced");

        let reply = login
            .authorize(&request, master)
            .expect("authorization should succeed")
            .to_vec();

        let mut joiner_store = FakeStore::default();
        let received = joiner
            .complete(&reply, &mut joiner_keys, &mut joiner_store)
            .expect("the login should complete");

        assert_eq!(
            received.expose(),
            master.expose(),
            "the new device's master key must equal the old device's"
        );
        assert!(
            joiner_store.master.is_some(),
            "the master key must be in the new device's platform store"
        );

        let data = account
            .vault
            .serialize()
            .expect("serialization should succeed");
        let opened = open_vault(&joiner_store, &data)
            .expect("the new device should open the old device's vault");
        assert_eq!(
            opened.master_key().expose(),
            old_store.master.as_ref().unwrap().expose()
        );
    }

    /// Before and after authorization the caller can read the session identifier and
    /// persist it.
    #[test]
    fn login_reports_the_session_for_persistence() {
        let (_k, _s, account) = registered();
        let mut login = Login::new().expect("the login should start");
        assert!(
            login.session_id().is_none(),
            "no session identifier before authorization"
        );
        assert!(login.joiner_device().is_none());

        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner =
            Joiner::new(&payload, "new-device").expect("the joiner session should start");
        let request = joiner
            .request(&mut keys)
            .expect("the request should be produced");
        let _reply = login
            .authorize(&request, account.vault.master_key())
            .expect("authorization should succeed");

        let session_id = login
            .session_id()
            .expect("a session identifier should exist after authorization");
        assert_eq!(
            session_id,
            joiner
                .session_id()
                .expect("both sides must derive the same identifier")
        );
        assert!(
            login.joiner_device().is_some(),
            "the peer identity should be available"
        );
        assert_eq!(login.used_sessions().len(), 1);
    }

    /// The same request cannot be authorized twice.
    #[test]
    fn the_same_request_cannot_be_authorized_twice() {
        let (_k, _s, account) = registered();
        let mut login = Login::new().expect("the login should start");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner =
            Joiner::new(&payload, "new-device").expect("the joiner session should start");
        let request = joiner
            .request(&mut keys)
            .expect("the request should be produced");
        let master = account.vault.master_key();

        login
            .authorize(&request, master)
            .expect("the first call should succeed");
        let error = login
            .authorize(&request, master)
            .expect_err("the second call must fail");
        assert!(
            matches!(
                error,
                Error::PairingAuthenticationFailed | Error::AuthMessageMalformed { .. }
            ),
            "got {error:?}"
        );
    }

    /// A request produced from the payload of **another** `Login` must be rejected.
    ///
    /// The authentication tag of Msg1 is derived from the **ECDH shared secret**, not
    /// from the master key: the master key is what this flow transfers, not a
    /// credential that authenticates the sender. Its confidentiality rests on only the
    /// person who scanned the QR code being able to compute that shared secret.
    ///
    /// The failing scenario is therefore a **session mismatch** (different ephemeral
    /// keys imply a different shared secret, so decryption must fail), as well as a
    /// joiner receiving a reply for another session. This test covers the former;
    /// [`a_reply_encrypted_for_another_session_cannot_be_opened`] covers the latter.
    #[test]
    fn a_request_from_another_login_is_rejected() {
        let (_k, _s, account) = registered();
        let first = Login::new().expect("the login should start");
        let payload_from_first = first.payload().clone();

        let mut second = Login::new().expect("the login should start");
        let mut keys = FakeKeys::new();
        let mut joiner = Joiner::new(&payload_from_first, "new-device")
            .expect("the joiner session should start");
        let request = joiner
            .request(&mut keys)
            .expect("the request should be produced");

        let error = second
            .authorize(&request, account.vault.master_key())
            .expect_err("a request from another device's payload must not be accepted");
        assert!(
            matches!(error, Error::PairingAuthenticationFailed),
            "got {error:?}"
        );
        assert!(
            second.session_id().is_none(),
            "a failure must leave no session identifier"
        );
    }

    /// A reply encrypted for **another session** cannot be opened by the joiner.
    ///
    /// `complete` decrypts Msg2 with the session key, which comes from the ECDH shared
    /// secret. A reply from another session therefore fails to decrypt and the master
    /// key never reaches storage.
    #[test]
    fn a_reply_encrypted_for_another_session_cannot_be_opened() {
        let (_k, _s, account) = registered();
        let mut keys = FakeKeys::new();

        let mut login_a = Login::new().expect("the login should start");
        let payload_a = login_a.payload().clone();
        let mut joiner_a =
            Joiner::new(&payload_a, "new-device").expect("the joiner session should start");
        let request_a = joiner_a
            .request(&mut keys)
            .expect("the request should be produced");
        login_a
            .authorize(&request_a, account.vault.master_key())
            .expect("session A should authorize");

        let mut login_b = Login::new().expect("the login should start");
        let payload_b = login_b.payload().clone();
        let mut joiner_b =
            Joiner::new(&payload_b, "new-device").expect("the joiner session should start");
        let request_b = joiner_b
            .request(&mut keys)
            .expect("the request should be produced");
        let reply_b = login_b
            .authorize(&request_b, account.vault.master_key())
            .expect("authorization should succeed");

        let mut store = FakeStore::default();
        let error = joiner_a
            .complete(&reply_b, &mut keys, &mut store)
            .expect_err("a reply from another session must not be accepted");
        assert!(
            matches!(error, Error::PairingAuthenticationFailed),
            "got {error:?}"
        );
        assert!(store.master.is_none(), "a failure must leave no master key");
    }

    /// A tampered reply from the old device is rejected.
    #[test]
    fn tampering_with_the_reply_is_detected() {
        let (_k, _s, account) = registered();
        let mut login = Login::new().expect("the login should start");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner =
            Joiner::new(&payload, "new-device").expect("the joiner session should start");
        let request = joiner
            .request(&mut keys)
            .expect("the request should be produced");
        let reply = login
            .authorize(&request, account.vault.master_key())
            .expect("authorization should succeed")
            .to_vec();

        for index in 0..reply.len() {
            let mut joiner =
                Joiner::new(&payload, "new-device").expect("the joiner session should start");
            let _ = joiner
                .request(&mut keys)
                .expect("the request should be produced");
            let mut tampered = reply.clone();
            tampered[index] ^= 0x01;
            let mut store = FakeStore::default();
            assert!(
                joiner.complete(&tampered, &mut keys, &mut store).is_err(),
                "byte {index} was flipped, yet still accepted"
            );
            assert!(store.master.is_none(), "a failure must leave no master key");
        }
    }

    /// `request` is idempotent: repeated calls return the same message rather than
    /// signing again.
    #[test]
    fn requesting_twice_returns_the_same_message() {
        let login = Login::new().expect("the login should start");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner =
            Joiner::new(&payload, "new-device").expect("the joiner session should start");
        let first = joiner
            .request(&mut keys)
            .expect("the request should be produced");
        let second = joiner
            .request(&mut keys)
            .expect("the request should be produced");
        assert_eq!(first, second);
        assert_eq!(
            keys.creates, 1,
            "the second request must not create a new identity"
        );
    }

    /// Recovery round trip: export, import, and write to storage, with the master key
    /// unchanged throughout.
    #[test]
    fn recovery_roundtrip_restores_the_master_key() {
        let (_k, mut store, account) = registered();
        let master = account.vault.master_key();
        let params = KdfParams::new(8, 1, 1).expect("the minimum parameters should be valid");
        let passphrase = SecretString::from("correct horse battery staple");

        let file =
            export_recovery_key(master, &passphrase, Some(params)).expect("export should succeed");
        let restored =
            import_recovery_key(&file, &passphrase, &mut store).expect("import should succeed");

        assert_eq!(restored.expose(), master.expose());
        let data = account
            .vault
            .serialize()
            .expect("serialization should succeed");
        open_vault(&store, &data).expect("the vault should open after recovery");
    }

    /// A wrong passphrase writes no master key at all.
    #[test]
    fn recovery_with_a_wrong_passphrase_leaves_storage_untouched() {
        let mut store = FakeStore::default();
        let master = MasterKey::generate().expect("randomness should be available");
        let params = KdfParams::new(8, 1, 1).expect("the minimum parameters should be valid");
        let file = export_recovery_key(&master, &SecretString::from("right"), Some(params))
            .expect("export should succeed");

        let error = import_recovery_key(&file, &SecretString::from("wrong"), &mut store)
            .expect_err("must fail with the wrong passphrase");
        assert!(
            matches!(error, Error::RecoveryAuthenticationFailed),
            "got {error:?}"
        );
        assert!(
            store.master.is_none(),
            "a failure must not write a master key"
        );
    }

    /// Export fails on an empty passphrase; otherwise the whole cost of Argon2id would
    /// be wasted.
    #[test]
    fn an_empty_passphrase_is_rejected() {
        let master = MasterKey::generate().expect("randomness should be available");
        let error = export_recovery_key(&master, &SecretString::from(""), None)
            .expect_err("an empty passphrase must be rejected");
        assert!(
            matches!(error, Error::RecoveryPassphraseEmpty),
            "got {error:?}"
        );
    }

    /// The store's hardware-backing claim is forwarded truthfully.
    #[test]
    fn hardware_backing_is_reported_truthfully() {
        let mut keys = FakeKeys::new();
        let mut soft = FakeStore::default();
        let result = registration(&mut keys, &mut soft, LABEL).expect("should succeed");
        assert!(!result.is_hardware_backed());

        let mut keys = FakeKeys::new();
        let mut hard = FakeStore {
            hardware: true,
            ..FakeStore::default()
        };
        let result = registration(&mut keys, &mut hard, LABEL).expect("should succeed");
        assert!(result.is_hardware_backed());
    }

    /// Interoperability check: an identity claimed by the other side must match the
    /// local one byte for byte.
    #[test]
    fn device_identity_comparison_works_both_ways() {
        let mut keys = FakeKeys::new();
        let actual = keys.get_or_create(LABEL).expect("should succeed");
        expect_device(&actual, actual.as_sec1_bytes()).expect("the same identity should pass");

        let other = keys.get_or_create("other").expect("should succeed");
        let error = expect_device(&other, actual.as_sec1_bytes())
            .expect_err("a different identity must fail");
        assert!(
            matches!(error, Error::DeviceIdentityMismatch),
            "got {error:?}"
        );
    }

    /// Signature and verification match each other, and the signature has a stable
    /// length.
    #[test]
    fn signatures_verify_and_have_a_stable_length() {
        let mut keys = FakeKeys::new();
        let public = keys.get_or_create(LABEL).expect("should succeed");
        let message = b"hello";
        let signature = keys.sign(LABEL, message).expect("signing should succeed");
        assert_eq!(signature.as_bytes().len(), SIGNATURE_LEN);
        verify_device(&public, message, &signature).expect("verification should pass");
        assert!(verify_device(&public, b"other", &signature).is_err());
    }

    /// Signing with an unknown label reports a clear error instead of panicking.
    #[test]
    fn signing_without_an_identity_fails_cleanly() {
        let mut keys = FakeKeys::new();
        let error = keys.sign("missing", b"x").expect_err("should fail");
        assert!(matches!(error, Error::DeviceKeyMissing), "got {error:?}");
    }

    /// A timestamp of `0` is rejected: it usually means the caller forgot to pass one.
    #[test]
    fn a_zero_timestamp_is_rejected() {
        assert!(check_now(0).is_err());
        assert_eq!(check_now(1).expect("a non-zero timestamp should pass"), 1);
    }

    /// The passphrase length can be queried, while the passphrase itself appears in no
    /// output.
    #[test]
    fn passphrase_length_is_available_without_exposing_the_passphrase() {
        let passphrase = SecretString::from("hunter2");
        assert_eq!(passphrase_len(&passphrase), 7);
        assert_eq!(passphrase_len(&SecretString::from("")), 0);
        assert_eq!(passphrase_len(&SecretString::from("口令")), 2);
    }

    /// `Debug` output contains no key material.
    #[test]
    fn debug_output_is_redacted() {
        let (_k, _s, account) = registered();
        let login = Login::new().expect("the login should start");
        let payload = login.payload().clone();
        let mut keys = FakeKeys::new();
        let mut joiner =
            Joiner::new(&payload, "new-device").expect("the joiner session should start");
        let _ = joiner
            .request(&mut keys)
            .expect("the request should be produced");

        let texts: [(&str, String); 3] = [
            ("Login", format!("{login:?}")),
            ("Joiner", format!("{joiner:?}")),
            ("MasterKey", format!("{:?}", account.vault.master_key())),
        ];
        let secrets: [(&str, String); 2] = [
            (
                "master key hex",
                account
                    .vault
                    .master_key()
                    .expose()
                    .iter()
                    .fold(String::new(), |mut acc, b| {
                        use core::fmt::Write as _;
                        let _ = write!(acc, "{b:02x}");
                        acc
                    }),
            ),
            (
                "master key decimal",
                account
                    .vault
                    .master_key()
                    .expose()
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ];
        for (name, text) in texts {
            for (secret_name, secret) in &secrets {
                assert!(
                    !text.contains(secret.as_str()),
                    "{name} Debug output contains the {secret_name}: {text}"
                );
            }
        }
    }

    /// The empty-vault helper produces a valid, openable file.
    #[test]
    fn an_empty_vault_is_openable() {
        let master = MasterKey::generate().expect("randomness should be available");
        let vault = empty_vault(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("the length is correct"),
        );
        let data = vault.serialize().expect("serialization should succeed");
        let mut store = FakeStore::default();
        store
            .store_master_key(&master)
            .expect("the write should succeed");
        let opened = open_vault(&store, &data).expect("the vault should open");
        assert!(opened.vault().is_empty());
    }

    /// The `&mut T` forwarding implementations are equivalent to a direct call.
    #[test]
    fn mutable_references_forward_correctly() {
        let mut keys = FakeKeys::new();
        let via_ref = {
            let borrowed: &mut FakeKeys = &mut keys;
            let dynamic: &mut dyn DeviceKeys = borrowed;
            dynamic.get_or_create(LABEL)
        }
        .expect("should succeed");
        let direct = keys.get_or_create(LABEL).expect("should succeed");
        assert_eq!(via_ref.as_sec1_bytes(), direct.as_sec1_bytes());
        assert_eq!(keys.creates, 1);
    }

    /// A vault with one entry and its serialized bytes, for the portable-container tests.
    fn vault_with_one_entry() -> (VaultFile, Vec<u8>) {
        let mut file = VaultFile::create().expect("randomness should be available");
        let entry = crate::vault::Entry::new(
            "GitHub".into(),
            Some("GitHub".into()),
            "alice".into(),
            crate::otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid secret"),
            crate::otp::Algorithm::Sha1,
            crate::otp::Digits::SIX,
            crate::vault::EntryKind::Totp { period: 30 },
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("the entry is valid");
        file.vault_mut().insert(entry).expect("the vault is empty");
        let data = file.serialize().expect("serialization should succeed");
        (file, data)
    }

    /// A clean device can restore its account from the **plain** container.
    #[test]
    fn a_plain_portable_vault_restores_on_a_clean_device() {
        let (file, data) = vault_with_one_entry();
        let packed = crate::portable::pack_plain(file.master_key(), &data).expect("it packs");
        let mut store = FakeStore::default();

        let restored = open_portable(&packed, &SecretString::from(String::new()), &mut store)
            .expect("the container is valid");
        match restored {
            PortableRestore::Vault(vault) => {
                assert_eq!(vault.vault().len(), 1, "the entry came along");
                assert_eq!(
                    vault.master_key().expose(),
                    file.master_key().expose(),
                    "the key the container carried is the one that opened the vault"
                );
            }
            other => panic!("expected a vault, actual {other:?}"),
        }
        assert!(
            store.master.is_some(),
            "the restored key must be in the platform store"
        );
    }

    /// The **encrypted** container needs its passphrase, and a wrong one changes nothing.
    #[test]
    fn an_encrypted_portable_vault_needs_the_right_passphrase() {
        let (file, data) = vault_with_one_entry();
        let passphrase = SecretString::from("correct horse battery staple".to_owned());
        let recovery = crate::recovery::export(
            file.master_key(),
            &passphrase,
            &crate::recovery::KdfParams::recommended(),
        )
        .expect("the recovery file is written");
        let packed = crate::portable::pack_encrypted(&recovery, &data).expect("it packs");

        // A wrong passphrase leaves the store untouched and reports authentication failure.
        let mut store = FakeStore::default();
        let err = open_portable(&packed, &SecretString::from("wrong".to_owned()), &mut store);
        assert!(
            matches!(err, Err(Error::RecoveryAuthenticationFailed)),
            "actual {err:?}"
        );
        assert!(
            store.master.is_none(),
            "a failed restore must not write a key"
        );

        // Omitting the passphrase is refused before any derivation runs.
        let err = open_portable(&packed, &SecretString::from(String::new()), &mut store);
        assert!(
            matches!(err, Err(Error::PortablePasswordRequired)),
            "actual {err:?}"
        );

        let restored = open_portable(&packed, &passphrase, &mut store).expect("it opens");
        assert!(matches!(restored, PortableRestore::Vault(_)));
    }

    /// A container whose key does not open its vault leaves the **previous** key in place.
    #[test]
    fn a_mismatched_portable_vault_rolls_the_key_back() {
        let other = VaultFile::create().expect("randomness should be available");
        let (file, _) = vault_with_one_entry();
        // Container: the vault of `file` under the key of `other`.
        let data = file.serialize().expect("serialization should succeed");
        let packed = crate::portable::pack_plain(other.master_key(), &data).expect("it packs");

        let (previous, _) = vault_with_one_entry();
        let previous_key = MasterKey::from_bytes(master_key_to_bytes(previous.master_key()))
            .expect("the length is correct");
        let mut store = FakeStore::default();
        store
            .store_master_key(&previous_key)
            .expect("the write should succeed");

        let err = open_portable(&packed, &SecretString::from(String::new()), &mut store);
        assert!(
            matches!(err, Err(Error::VaultDecryptionFailed)),
            "actual {err:?}"
        );
        let kept = store.load_master_key().expect("the store is readable");
        assert_eq!(
            kept.map(|key| key.expose().to_vec()),
            Some(previous_key.expose().to_vec()),
            "the device must stay on the key it had"
        );
    }

    /// The old key-only file is recognized and **writes nothing**.
    #[test]
    fn a_key_only_file_is_reported_and_changes_nothing() {
        let master = MasterKey::generate().expect("randomness should be available");
        let passphrase = SecretString::from("passphrase".to_owned());
        let file = crate::recovery::export(
            &master,
            &passphrase,
            &crate::recovery::KdfParams::recommended(),
        )
        .expect("the recovery file is written");

        let mut store = FakeStore::default();
        let restored = open_portable(&file, &passphrase, &mut store).expect("it is a valid file");
        assert!(matches!(restored, PortableRestore::KeyOnly));
        assert!(
            store.master.is_none(),
            "a key-only file has no entries to restore, so nothing is written"
        );
    }

    /// A bare vault file is refused with the diagnosis that says what to export instead.
    #[test]
    fn a_bare_vault_file_is_refused_by_the_restore_path() {
        let (_, data) = vault_with_one_entry();
        let mut store = FakeStore::default();
        let err = open_portable(&data, &SecretString::from(String::new()), &mut store);
        assert!(
            matches!(err, Err(Error::PortableVaultFileWithoutKey)),
            "actual {err:?}"
        );
        assert!(store.master.is_none());
    }
}
