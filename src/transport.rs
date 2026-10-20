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

//! Transport abstraction: this module only knows how to move a run of bytes to a peer. It
//! knows nothing about WiFi, QR codes or Bluetooth.
//!
//! The boundary between this module and the concrete channels follows from the core
//! library's properties: it has `#![forbid(unsafe_code)]` and performs no I/O, while every
//! real transport needs I/O — UDP multicast needs a socket, QR codes need a camera and a
//! screen, Quick Share needs platform APIs. This module defines what one synchronization
//! exchange looks like; the platform side implements how the bytes get across.
//!
//! The same protocol also runs in-process without a network. Protocol correctness (which
//! payload arrives first, how conflicts are reported, how replays are blocked) is therefore
//! verified in a single process rather than by pairing two real devices; see the
//! implementation contract on [`Transport`] and the tests in this module.
//!
//! # Three transports, one protocol
//!
//! | Transport | Roster | Per-message limit | Notes |
//! |-----------|--------|-------------------|-------|
//! | QR code | two-party | yes (a few kilobytes per code; split across codes when it does not fit) | single-use, out-of-band |
//! | LAN (QWBP) | multi-party | none (reliable byte stream) | primary transport |
//! | Hotspot | multi-party | none | a LAN variant; platform differences live in the implementation |
//!
//! [`TransportCapabilities`] describes every difference between them, so [`SyncSession`]
//! needs no per-transport branch.
//!
//! **A "message" is not a single physical artifact.** When a QR code cannot hold the
//! payload, the channel may display several codes in sequence and let the peer scan them
//! one by one and reassemble the payload (animated QR codes); the core library is
//! deliberately unaware of that layer. The channel declares how many bytes one message can
//! carry (the sum over the codes), while how frames are cut and reassembled is the
//! channel's business. The core library therefore never needs to know about frames: it
//! only ever compares byte counts, see [`TransportCapabilities::max_message_len`].
//!
//! # Two-party and multi-party channels
//!
//! A two-party channel starts transferring immediately: only one peer will ever show up,
//! so there is nobody to wait for. On a multi-party channel the initiator decides when to
//! start; otherwise the device that connects first would finish exchanging payloads before
//! the others arrive, and the result of that round would depend on who connected first.
//!
//! That rule is exposed as [`TransportCapabilities::needs_start_signal`] rather than left
//! to `if` statements at the call sites because it is a protocol property: a single side
//! getting it wrong ends in a sync that "succeeded" but is missing records.

use core::fmt;

use crate::error::{Error, Result};
use crate::sync::{self, MergedRecord, Payload, PayloadKind, SeenSyncIds, SyncId};
use crate::vault::{MasterKey, Vault};
use qualia_dik::DeviceId;

/// How many parties take part in one sync.
///
/// Decides whether the initiator's start signal must be awaited. The distinction has to be
/// declared by the transport rather than guessed by the caller: the same code is two-party
/// over QR codes and may be multi-party for the same use over a LAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Roster {
    /// Exactly two parties. Transfer starts as soon as they connect.
    TwoParty,
    /// Three or more parties. The initiator decides when to start.
    MultiParty,
}

impl Roster {
    /// Whether the initiator's start signal must be awaited before transferring.
    #[must_use]
    pub const fn needs_start_signal(self) -> bool {
        matches!(self, Self::MultiParty)
    }
}

/// The recipient of a message.
///
/// Every record in a payload is protected by the master key, so broadcasting leaks no
/// content by itself. The recipient is still an explicit parameter: in a multi-device sync,
/// "forward B's changes to C in this round" and "broadcast my own changes" are two different
/// actions, and sending to everyone when one peer was meant should be visible in the
/// signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    /// Send to this peer only.
    One(DeviceId),
    /// Send to every peer in the current session.
    All,
}

/// What a transport can do.
///
/// # Capabilities are declared, not probed
///
/// The answer has to be available before the exchange starts: the caller picks the mode up
/// front and can send the user to a LAN transfer when the payload does not fit, without
/// first displaying a code to be scanned.
///
/// # One message may span several physical artifacts
///
/// When a QR code cannot hold the whole payload, the channel may display the same message
/// as several codes in sequence (animated QR codes) and let the peer scan them one by one
/// and reassemble the original bytes; other channels may have their own fragmentation
/// (several files, several clipboard chunks). The core library is deliberately unaware of
/// that layer:
///
/// - [`TransportCapabilities::max_message_len`] is the number of bytes **one message** (all
///   artifacts together) can carry, not the size of a single artifact;
/// - there is no frame count field, and there must not be one: how many codes are shown and
///   how large each one is are the channel's business, and every extra field is another
///   chance for the declaration to disagree with the implementation.
///
/// Both places must use **one and the same computation**: the value declared here and the
/// capacity the channel actually uses when splitting frames. The platform-side multi-frame
/// QR channel obtains it from `QrProfile::exchange_capacity(max_frames)` in
/// `qualia-transport`, which is also the capacity used for rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCapabilities {
    /// Roster.
    pub roster: Roster,
    /// Per-message byte limit; `None` means a reliable byte stream that takes the whole
    /// payload in one go.
    ///
    /// QR codes are `Some`: their capacity depends on the version, and a payload that does
    /// not fit never will. A LAN channel is `None`: it is a byte stream and sends payloads
    /// with thousands of records just as well.
    ///
    /// **A multi-frame channel declares the sum over all codes**, not the capacity of a
    /// single code (see "One message may span several physical artifacts" above).
    pub max_message_len: Option<usize>,
    /// Largest QR version this channel may display (1–40).
    ///
    /// `None` means the channel does not display QR codes. **This value belongs to the
    /// platform, not to the data set**: the same data set may fail to fit on one platform
    /// and fit easily on another, and what to do when it does not fit (send the user to a
    /// LAN transfer) is a platform decision as well.
    pub max_qr_version: Option<u8>,
    /// Whether this channel may be used only once.
    ///
    /// QR codes are `true`: one code carries one exchange, and reusing the same code opens
    /// a path around replay protection. A LAN channel is `false`.
    pub single_use: bool,
    /// Whether this channel can carry the **whole** payload (the full-provision mode).
    ///
    /// When `false`, only link establishment is possible: the channel itself is used to
    /// exchange addresses/keys, and the payload travels over a separate byte stream.
    pub can_carry_payload: bool,
}

impl TransportCapabilities {
    /// A **byte-stream** channel (LAN, hotspot, Quick Share).
    ///
    /// The whole payload travels over this channel; there is no per-message limit and the
    /// channel can be used repeatedly.
    #[must_use]
    pub const fn stream(roster: Roster) -> Self {
        Self {
            roster,
            max_message_len: None,
            max_qr_version: None,
            single_use: false,
            can_carry_payload: true,
        }
    }

    /// A **fixed-size** channel (QR codes).
    ///
    /// `max_message_len` is the number of bytes this channel can carry in **one message**:
    /// the capacity of a single code when there is only one (computed on the platform side
    /// from the error-correction level), and the
    /// [sum over all codes](TransportCapabilities) when there are several. It takes no
    /// version number as input: how many bytes version 40 holds depends on the
    /// error-correction level and the encoding mode, which is the platform library's
    /// business.
    ///
    /// **Multi-frame channels must take this number from the same computation** that splits
    /// frames: the declared limit and the capacity the channel actually uses must agree,
    /// otherwise the core library approves a share that the channel cannot render.
    /// Multi-frame QR codes use `QrProfile::exchange_capacity(max_frames)` from
    /// `qualia-transport`.
    #[must_use]
    pub const fn qr(max_qr_version: u8, max_message_len: usize) -> Self {
        Self {
            roster: Roster::TwoParty,
            max_message_len: Some(max_message_len),
            max_qr_version: Some(max_qr_version),
            single_use: true,
            can_carry_payload: true,
        }
    }

    /// Whether this channel can carry a payload of `len` bytes.
    ///
    /// `len` is the size of **one message**; on a multi-frame channel it is the sum over
    /// all frames, not the size of a single frame. This is the **only** test for "does it
    /// fit": planning and sending must both go through it, otherwise a share can be planned
    /// as fitting and then fail to send.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TransportMessageTooLarge`] carrying the number of bytes actually
    /// needed, so that the caller can tell the user how much is missing rather than just
    /// "too large".
    pub fn check_fits(&self, len: usize) -> Result<()> {
        match self.max_message_len {
            Some(limit) if len > limit => {
                Err(Error::TransportMessageTooLarge { needed: len, limit })
            }
            _ => Ok(()),
        }
    }

    /// Whether the initiator's start signal must be awaited before transferring.
    #[must_use]
    pub const fn needs_start_signal(&self) -> bool {
        self.roster.needs_start_signal()
    }
}

/// A channel that can move sync payloads.
///
/// # Implementation contract
///
/// 1. **`receive` must report the sender truthfully**, not just hand back bytes. The
///    `sender` inside the payload is self-reported and can therefore only serve as a
///    **cross-check**; only the channel knows who actually sent the message. On a broadcast
///    channel (LAN multicast) any device can replay a payload someone else sent unchanged,
///    so "the payload says it is from B" and "C actually sent it" can hold at the same time.
///    The core library turns that comparison into a hard check
///    ([`Error::SyncSenderMismatch`]), so misreporting the sender gains an implementation
///    nothing and only makes the sync fail.
/// 2. **`send` must respect [`Recipient`]**: `Recipient::One` must not degrade into a
///    broadcast.
/// 3. **`receive` must not block indefinitely**. When the channel has no message it returns
///    [`Error::SyncNoSessionFound`] and the caller decides whether to wait longer. The core
///    library has no clock, so how long to wait is up to the implementation and the caller
///    together.
/// 4. **A `single_use` channel must return [`Error::TransportAlreadyUsed`] on its second
///    use**.
///
/// Platform-side implementations typically keep sockets, buffers and state machines
/// internally, while `send`/`receive` semantically just put and take one message. `&self`
/// leaves the choice of interior mutability (`Mutex`, atomics, a lock-free queue) to the
/// implementation and lets it send and receive on several threads at once, which LAN
/// channels have to do.
pub trait Transport {
    /// What this channel can do.
    fn capabilities(&self) -> TransportCapabilities;

    /// This device's identifier.
    ///
    /// It fills in the `sender` of outgoing payloads, so both sides of an exchange see the
    /// same value.
    fn local_device(&self) -> DeviceId;

    /// Sends one message.
    fn send(&self, to: Recipient, message: &[u8]) -> Result<()>;

    /// Receives one message and hands back the **bytes** and the **sender the channel
    /// claims**.
    ///
    /// Returns [`Error::SyncNoSessionFound`] when no message is currently available.
    fn receive(&self) -> Result<(DeviceId, Vec<u8>)>;

    /// Every peer in the current session.
    ///
    /// Zero or one element on a two-party channel, possibly several on a multi-party one.
    /// This defines the meaning of `Recipient::All`. It returns a `Vec` rather than an
    /// iterator because callers usually need the count first (to decide whether to wait for
    /// the start signal), and an iterator would turn that into an implicit second pass.
    fn peers(&self) -> Result<Vec<DeviceId>>;
}

/// The result of one sync.
#[derive(Debug)]
pub struct SyncOutcome {
    /// Identifier of the payload just processed.
    ///
    /// The caller should record it (or hand it to [`SeenSyncIds`]); the next time the same
    /// identifier arrives, [`SyncSession::receive`] rejects it outright.
    pub sync_id: SyncId,
    /// Merge result: how many records were added, deleted, or need adjudication.
    pub merge: sync::MergeOutcome,
}

impl SyncOutcome {
    /// Whether this sync changed **nothing at all**.
    ///
    /// This is not the same as a failed merge: a peer holding no changes the local vault
    /// lacks is a normal outcome. The condition is exposed as a method rather than left to
    /// the caller so that it cannot be assembled wrongly.
    #[must_use]
    pub fn made_no_change(&self) -> bool {
        self.merge.made_no_change()
    }

    /// Whether this sync left conflicts that the user has to adjudicate.
    #[must_use]
    pub fn needs_adjudication(&self) -> bool {
        self.merge.needs_adjudication()
    }
}

impl fmt::Display for SyncOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "added {}, tombstones {}, deletions applied {}, unchanged {}, conflicts {}",
            self.merge.added,
            self.merge.tombstones_added,
            self.merge.deletions_applied,
            self.merge.unchanged,
            self.merge.conflicts.len()
        )
    }
}

/// Which route to take when sharing the current state over a channel.
///
/// # The answer is needed before anything is displayed
///
/// Whether the payload fits has to be known before a code is shown to be scanned, and
/// [`SyncSession::send`] seals and sends in one step, leaving the caller no chance to look
/// at the size first. This planning step therefore performs exactly the same sealing as
/// sending and only splits the outcome into two routes.
///
/// # "Does not fit" is another route, not a failure
///
/// When the payload does not fit, the answer is not an error: a **request**
/// ([`PayloadKind::Request`], which carries no records and is far smaller than any full
/// state) goes out first, and the large payload is left to a byte-stream channel (a LAN
/// transfer) or to a later sync. It is an enum rather than an error so that the change of
/// route is visible in the type instead of having to be read out of an error kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharePlan {
    /// The whole payload fits this channel; send it directly.
    FullPayload {
        /// Size in bytes after sealing.
        len: usize,
    },
    /// Does not fit: send a request first and move the payload over another channel.
    LinkEstablishment {
        /// Number of bytes the payload actually needs.
        needed: usize,
        /// Largest number of bytes this channel can carry.
        limit: usize,
    },
}

impl SharePlan {
    /// Whether a byte-stream channel must be established first.
    #[must_use]
    pub const fn needs_link(self) -> bool {
        matches!(self, Self::LinkEstablishment { .. })
    }
}

impl fmt::Display for SharePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::FullPayload { len } => write!(f, "full payload ({len} bytes)"),
            Self::LinkEstablishment { needed, limit } => {
                write!(
                    f,
                    "does not fit: {needed} bytes needed, limit {limit} bytes"
                )
            }
        }
    }
}

/// One synchronization session.
///
/// # It does not own the transport
///
/// Every method takes the transport as a parameter. Real channels (a LAN socket) live as
/// long as the platform's network stack keeps them, and one sync can span as much time as
/// the user needs to finish scanning, so the session must not be tied to the channel's
/// lifetime.
///
/// # It borrows `seen` instead of owning it
///
/// The replay log has to survive **across sessions** (otherwise restarting the app would
/// make every old payload replayable), so the caller owns it. The session only borrows it
/// and records an identifier **after** the payload was successfully decrypted and merged.
pub struct SyncSession<'a> {
    /// This device's master key, used to seal and open payloads.
    master: &'a MasterKey,
    /// This device's vault, the target of the merge.
    vault: &'a mut Vault,
    /// Replay log that survives across sessions.
    seen: &'a mut SeenSyncIds,
    /// Accept payloads only from these devices.
    ///
    /// Empty means "accept any peer", which is the state **after** a link has been
    /// established: the channel has confirmed the peer out-of-band (QR code) or through
    /// pairing. Payloads arriving in a LAN multicast hall must come from the list, or any
    /// device on the same subnet could write records into the vault.
    allowed_senders: Vec<DeviceId>,
}

impl<'a> SyncSession<'a> {
    /// Creates a session that accepts only the listed devices.
    ///
    /// The payload itself is authenticated with the master key, so the list is **not** a
    /// confidentiality barrier: an attacker without the master key cannot produce a record
    /// that authenticates. The list guards against something else, namely replaying a
    /// payload **someone else signed** unchanged so that the user believes they synced with
    /// that peer. On LAN multicast this costs an attacker nothing.
    #[must_use]
    pub fn restricted(
        master: &'a MasterKey,
        vault: &'a mut Vault,
        seen: &'a mut SeenSyncIds,
        allowed_senders: Vec<DeviceId>,
    ) -> Self {
        Self {
            master,
            vault,
            seen,
            allowed_senders,
        }
    }

    /// Creates a session that accepts any peer.
    ///
    /// Use it only after the channel has **already** confirmed the peer's identity (an
    /// out-of-band QR code, a completed pairing).
    #[must_use]
    pub fn open(master: &'a MasterKey, vault: &'a mut Vault, seen: &'a mut SeenSyncIds) -> Self {
        Self {
            master,
            vault,
            seen,
            allowed_senders: Vec::new(),
        }
    }

    /// Seals the local vault into a payload and sends it.
    ///
    /// # It does **not** record this payload in the replay log
    ///
    /// The log holds **received** payloads only; its meaning is "inbound payloads already
    /// processed", not "payloads seen". Recording an outgoing payload would make this device
    /// reject its own payload when a peer sends it back or when the user syncs back and
    /// forth between two devices.
    ///
    /// # The payload kind is the caller's choice
    ///
    /// `kind` selects "my full state" or "send me yours". It is not fixed here because
    /// whether the state travels along is a protocol-level decision: one round suffices on
    /// a LAN (state exchange), whereas over QR codes a small request fits into the code and
    /// the large payload comes back over a byte-stream channel.
    ///
    /// # Errors
    ///
    /// Sealing failures (see [`Payload::from_vault`]), a payload that does not fit the
    /// channel ([`Error::TransportMessageTooLarge`]), or any failure of the channel itself.
    pub fn send(
        &self,
        transport: &dyn Transport,
        to: Recipient,
        kind: PayloadKind,
    ) -> Result<SyncId> {
        let payload = match kind {
            PayloadKind::Vault => {
                self.ensure_icons_can_travel(transport)?;
                Payload::from_vault(self.master, transport.local_device(), self.vault)?
            }
            PayloadKind::Request => Payload::request(transport.local_device())?,
        };
        let sealed = payload.seal(self.master)?;

        transport.capabilities().check_fits(sealed.len())?;
        transport.send(to, &sealed)?;
        Ok(payload.sync_id)
    }

    /// Refuses a channel that cannot carry icons when the vault holds any.
    ///
    /// An icon is up to 64 KiB, and a channel with a declared message limit (a QR code, for
    /// instance) either cannot hold the payload at all or would only fit by dropping the picture.
    /// The check is **before sealing** and before the capacity check, so the user is told what is
    /// actually wrong: "this channel cannot move icons", not "the payload is too large". The
    /// error is named rather than a silent drop because a sync that quietly loses what the user
    /// sees is worse than one that is refused.
    ///
    /// A channel with no message limit (a LAN connection) carries the vault as it is.
    fn ensure_icons_can_travel(&self, transport: &dyn Transport) -> Result<()> {
        if transport.capabilities().max_message_len.is_some()
            && self.vault.iter().any(|(_, entry)| entry.has_icon())
        {
            return Err(Error::SyncIconRequiresByteTransport);
        }
        Ok(())
    }

    /// Plans which route this share takes; the answer is known **before** anything is
    /// displayed.
    ///
    /// # It sends nothing
    ///
    /// It only seals and compares, so the caller can ask first, while the user has not
    /// confirmed yet, and then decide whether to display a code.
    ///
    /// # It plans "send my full state"
    ///
    /// A request ([`PayloadKind::Request`]) carries no records and is always small, so it
    /// needs no planning. What has to be known in advance is whether the full state fits.
    ///
    /// # It costs one full sealing pass
    ///
    /// Per-record encryption, compression and the outer AEAD, on the order of milliseconds.
    /// The result is not cached: a cache would keep a copy of the plaintext state (or of the
    /// ciphertext and its parameters) inside the session, and that copy could go stale when
    /// the vault or the master key changes.
    ///
    /// # Errors
    ///
    /// Exactly the sealing step of [`SyncSession::send`], see [`Payload::from_vault`] and
    /// [`Payload::seal`].
    pub fn plan_share(&self, transport: &dyn Transport) -> Result<SharePlan> {
        self.ensure_icons_can_travel(transport)?;
        let payload = Payload::from_vault(self.master, transport.local_device(), self.vault)?;
        let sealed = payload.seal(self.master)?;
        Ok(match transport.capabilities().max_message_len {
            Some(limit) if sealed.len() > limit => SharePlan::LinkEstablishment {
                needed: sealed.len(),
                limit,
            },
            _ => SharePlan::FullPayload { len: sealed.len() },
        })
    }

    /// Receives one message and merges its records into the local vault.
    ///
    /// # Order (no step may move)
    ///
    /// 1. **Is the peer on the list** — if not, drop the message. This blocks a third party
    ///    replaying someone else's payload unchanged.
    /// 2. **Has this payload been processed** — if so, reject it and do **not** record it
    ///    again.
    /// 3. **Open the sealed payload** — on failure, reject. Only after this step is
    ///    `sender` trustworthy (it is part of the AAD).
    /// 4. **Does the payload's self-reported sender match the channel's claim** — if not,
    ///    reject. See [`Error::SyncSenderMismatch`].
    /// 5. **Decrypt and merge record by record** — this is the step that touches the vault.
    /// 6. **Record the identifier** — only if every step above succeeded.
    ///
    /// Step 6 comes last because recording before decryption would let an attacker send a
    /// **garbage** payload claiming identifier X and thereby have the real X rejected
    /// forever.
    ///
    /// # Errors
    ///
    /// Any failing step returns its own error and leaves **both the vault and the log
    /// unchanged**. The one exception is a merge that fails midway (copying key material):
    /// the records merged so far stay, because atomicity would have to span two stores.
    pub fn receive(&mut self, transport: &dyn Transport) -> Result<SyncOutcome> {
        let (claimed_sender, message) = transport.receive()?;

        if !self.allowed_senders.is_empty() && !self.allowed_senders.contains(&claimed_sender) {
            return Err(Error::SyncSenderMismatch);
        }

        let header = Payload::peek(&message)?;
        if self.seen.contains(&header.sync_id) {
            return Err(Error::SyncAlreadyApplied);
        }

        let payload = Payload::open(self.master, &message)?;

        if payload.sender != claimed_sender {
            return Err(Error::SyncSenderMismatch);
        }

        let opened = payload.open_records(self.master)?;
        let records: Vec<MergedRecord> = opened
            .into_iter()
            .map(sync::OpenedRecord::into_merged)
            .collect();
        let mut set = sync::RecordSet::new();
        for record in records {
            set.insert(record);
        }
        let merge = sync::merge_into(self.vault, &set)?;

        self.seen.record(payload.sync_id)?;

        Ok(SyncOutcome {
            sync_id: payload.sync_id,
            merge,
        })
    }
}

/// # "The channel has no message" and "the payload was rejected" must stay distinct
///
/// [`SyncSession`] deliberately offers no `try_receive`-style convenience that continues on
/// failure: mixing the two cases into one return value is the shortest path to a hole in
/// replay protection, since the caller may write `let _ = session.receive(...)` and silently
/// drop [`Error::SyncAlreadyApplied`].
///
/// Callers distinguish [`Error::SyncNoSessionFound`] (keep waiting) from every other error
/// (reject).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{Algorithm, Digits, OtpSecret};
    use crate::sync::{RecordSet, merge_into};
    use crate::vault::{
        Entry, EntryIcon, EntryId, EntryKind, GroupChild, IconMime, Timestamp, Vault as VaultAlias,
    };

    /// An in-memory channel used to exercise the protocol without a network.
    ///
    /// It only moves bytes and makes no protocol decisions; every decision lives in
    /// [`SyncSession`]. A channel that "helps" (by de-duplicating, say) would mask real
    /// defects in the protocol.
    struct MemoryTransport {
        /// This device's identifier.
        me: DeviceId,
        /// Outbound queue: `(recipient, sender, bytes)`.
        outbox: std::sync::Mutex<Vec<(Recipient, DeviceId, Vec<u8>)>>,
        /// Inbound queue: `(sender claimed by the channel, bytes)`.
        inbox: std::sync::Mutex<Vec<(DeviceId, Vec<u8>)>>,
        /// Capabilities this channel claims.
        caps: TransportCapabilities,
        /// Peers this channel claims.
        peers: Vec<DeviceId>,
    }

    impl MemoryTransport {
        fn new(me: DeviceId, caps: TransportCapabilities) -> Self {
            Self {
                me,
                outbox: std::sync::Mutex::new(Vec::new()),
                inbox: std::sync::Mutex::new(Vec::new()),
                caps,
                peers: Vec::new(),
            }
        }

        fn with_peers(mut self, peers: Vec<DeviceId>) -> Self {
            self.peers = peers;
            self
        }

        /// Moves this channel's outbound queue into another channel's inbound queue.
        ///
        /// # The outbound queue is **not** cleared
        ///
        /// One broadcast addresses N peers, so delivery must be callable N times; a caller
        /// that wants a fresh round calls [`MemoryTransport::clear_outbox`] explicitly.
        ///
        /// With `honest` set to `false` the claimed sender is replaced, which models a third
        /// party replaying someone else's payload unchanged on a broadcast channel.
        fn deliver_to(&self, target: &MemoryTransport, honest: bool) {
            let outbox = self.outbox.lock().expect("lock not poisoned");
            let mut inbox = target.inbox.lock().expect("lock not poisoned");
            for (recipient, sender, bytes) in outbox.iter() {
                let addressed = match recipient {
                    Recipient::All => true,
                    Recipient::One(id) => *id == target.me,
                };
                if !addressed {
                    continue;
                }
                let claimed = if honest { *sender } else { self.me };
                inbox.push((claimed, bytes.clone()));
            }
        }

        /// Discards every message in the outbound queue.
        ///
        /// This is the boundary between sync rounds: clearing it at the start of each round
        /// keeps the previous round's payload from being delivered twice, which the receiver
        /// would report as [`Error::SyncAlreadyApplied`].
        fn clear_outbox(&self) {
            self.outbox.lock().expect("lock not poisoned").clear();
        }

        /// Pushes a message straight into the inbound queue (models an attacker).
        fn inject(&self, claimed_sender: DeviceId, bytes: Vec<u8>) {
            self.inbox
                .lock()
                .expect("lock not poisoned")
                .push((claimed_sender, bytes));
        }
    }

    impl Transport for MemoryTransport {
        fn capabilities(&self) -> TransportCapabilities {
            self.caps
        }

        fn local_device(&self) -> DeviceId {
            self.me
        }

        fn send(&self, to: Recipient, message: &[u8]) -> Result<()> {
            self.outbox
                .lock()
                .expect("lock not poisoned")
                .push((to, self.me, message.to_vec()));
            Ok(())
        }

        fn receive(&self) -> Result<(DeviceId, Vec<u8>)> {
            let mut inbox = self.inbox.lock().expect("lock not poisoned");
            if inbox.is_empty() {
                return Err(Error::SyncNoSessionFound);
            }
            Ok(inbox.remove(0))
        }

        fn peers(&self) -> Result<Vec<DeviceId>> {
            Ok(self.peers.clone())
        }
    }

    fn a_device(seed: u8) -> (DeviceId, MasterKey, Vault) {
        let master = MasterKey::generate().expect("OS random source is available");
        (DeviceId::from_bytes([seed; 32]), master, Vault::new())
    }

    fn sample_entry(name: &str, updated_at: u64) -> Entry {
        Entry::new(
            name.into(),
            Some("组织".into()),
            "user@example.com".into(),
            OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid Base32"),
            Algorithm::Sha1,
            Digits::SIX,
            EntryKind::Totp { period: 30 },
            String::new(),
            Timestamp::from(1_700_000_000_u64),
            Timestamp::from(updated_at),
        )
        .expect("the fields are valid")
    }

    /// A full two-party round trip: A's entry shows up in B's vault.
    #[test]
    fn a_two_party_exchange_moves_entries() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        vault_a
            .insert(sample_entry("A's entry", 1_700_000_000))
            .expect("random source is available");

        let caps = TransportCapabilities::stream(Roster::TwoParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a]);

        let mut seen_a = SeenSyncIds::new();
        let mut seen_b = SeenSyncIds::new();

        let session_a = SyncSession::open(&master, &mut vault_a, &mut seen_a);
        session_a
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("send");

        ta.deliver_to(&tb, true);

        let outcome = {
            let mut session_b = SyncSession::open(&master, &mut vault_b, &mut seen_b);
            session_b.receive(&tb).expect("receive")
        };

        assert_eq!(
            outcome.merge.added, 1,
            "one record should have been merged: {outcome}"
        );
        assert_eq!(vault_b.len(), 1);
        assert!(
            !outcome.needs_adjudication(),
            "identical content must not count as a conflict"
        );
        assert_eq!(seen_b.len(), 1, "a received payload must be recorded");

        assert_eq!(
            seen_a.len(),
            0,
            "an outgoing payload must not enter the replay log"
        );

        ta.deliver_to(&tb, true);
        let again = {
            let mut session_b = SyncSession::open(&master, &mut vault_b, &mut seen_b);
            session_b.receive(&tb)
        };
        assert!(
            matches!(again, Err(Error::SyncAlreadyApplied)),
            "a duplicate payload was not rejected, got {again:?}"
        );
    }

    /// The group tree and the icons travel with the entries: two devices that sync hold the
    /// same parents, the same mixed order and the same pictures.
    #[test]
    fn a_two_party_exchange_moves_the_tree_and_the_icons() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let icon =
            EntryIcon::new(IconMime::Jpeg, vec![0xFF, 0xD8, 0xFF, 0xE0]).expect("a small icon");
        let entry = vault_a
            .insert(
                sample_entry("inside a nested group", 1_700_000_000).with_icon(Some(icon.clone())),
            )
            .expect("random source is available");
        let work = vault_a
            .create_group("Work".to_owned())
            .expect("creation succeeds");
        let sub = vault_a
            .create_group_in(&work, "Sub".to_owned())
            .expect("creation succeeds");
        vault_a
            .set_children(
                &work,
                vec![GroupChild::Group(sub), GroupChild::Entry(entry)],
            )
            .expect("the list is valid");
        let expected_children = vault_a.children_of(&work).expect("it exists").to_vec();

        let caps = TransportCapabilities::stream(Roster::TwoParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a]);
        let mut seen_a = SeenSyncIds::new();
        let mut seen_b = SeenSyncIds::new();

        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("send");
        ta.deliver_to(&tb, true);
        let outcome = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("receive");

        assert!(
            !outcome.needs_adjudication(),
            "a first sync of a consistent tree must not be a conflict: {outcome}"
        );
        assert_eq!(
            vault_b.children_of(&work).map(|children| children.to_vec()),
            Some(expected_children),
            "the mixed order of entries and child groups survives"
        );
        assert_eq!(vault_b.parent_of(&sub), Some(work));
        assert_eq!(vault_b.depth_of(&sub), Some(2));
        assert_eq!(vault_b.group_of(&entry), Some(&work));
        assert_eq!(
            vault_b.get(&entry).and_then(|entry| entry.icon.clone()),
            Some(icon),
            "the picture travels inside the entry record"
        );
    }

    /// **Replay: a third party forwards B's payload to C unchanged.**
    ///
    /// The payload is cryptographically valid; B really did sign it. The sender list is
    /// what rejects it.
    #[test]
    fn a_replayed_payload_from_a_third_party_is_rejected() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);
        vault_b
            .insert(sample_entry("B's entry", 1_700_000_000))
            .expect("random source is available");

        let caps = TransportCapabilities::stream(Roster::MultiParty);

        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a, id_c]);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b, id_c]);
        let tc = MemoryTransport::new(id_c, caps).with_peers(vec![id_a]);

        let mut seen_b = SeenSyncIds::new();
        let session_b = SyncSession::open(&master, &mut vault_b, &mut seen_b);
        session_b
            .send(&tb, Recipient::All, PayloadKind::Vault)
            .expect("send");

        let b_payload = tb
            .outbox
            .lock()
            .expect("lock not poisoned")
            .first()
            .map(|(_, _, bytes)| bytes.clone())
            .expect("B's outbox should hold that payload");

        tb.deliver_to(&ta, true);
        let mut seen_a = SeenSyncIds::new();
        let outcome_a = {
            let mut session_a = SyncSession::open(&master, &mut vault_a, &mut seen_a);
            session_a.receive(&ta).expect("A receives it normally")
        };
        assert_eq!(outcome_a.merge.added, 1, "A should have taken B's record");

        ta.send(Recipient::One(id_c), &b_payload).expect("forward");
        ta.deliver_to(&tc, true);

        let mut seen_c = SeenSyncIds::new();
        let mut session_c = SyncSession::restricted(&master, &mut vault_c, &mut seen_c, vec![id_a]);
        let result = session_c.receive(&tc);
        assert!(
            matches!(result, Err(Error::SyncSenderMismatch)),
            "a forwarded payload was not rejected, got {result:?}"
        );
        assert_eq!(
            vault_c.len(),
            0,
            "a rejected payload must not modify the vault"
        );
        assert_eq!(seen_c.len(), 0, "a rejected payload must not be recorded");
    }

    /// A payload from a peer outside the list is dropped.
    #[test]
    fn a_payload_from_an_unlisted_peer_is_rejected() {
        let (id_a, master, _) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);
        vault_b
            .insert(sample_entry("B's entry", 1_700_000_000))
            .expect("random source is available");

        let caps = TransportCapabilities::stream(Roster::MultiParty);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_c]);
        let tc = MemoryTransport::new(id_c, caps).with_peers(vec![id_b]);

        let mut seen_b = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .send(&tb, Recipient::All, PayloadKind::Vault)
            .expect("send");
        tb.deliver_to(&tc, true);

        let mut seen_c = SeenSyncIds::new();
        let result = {
            let mut session_c =
                SyncSession::restricted(&master, &mut vault_c, &mut seen_c, vec![id_a]);
            session_c.receive(&tc)
        };
        assert!(
            matches!(result, Err(Error::SyncSenderMismatch)),
            "a peer outside the list was not rejected, got {result:?}"
        );
        assert_eq!(vault_c.len(), 0);
    }

    /// **A garbage payload must not record its identifier in the log.**
    ///
    /// Recording before decryption would let an attacker send garbage claiming identifier
    /// X and have the real X rejected forever.
    #[test]
    fn a_garbage_payload_does_not_poison_the_seen_log() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, _) = a_device(2);
        let caps = TransportCapabilities::stream(Roster::TwoParty);

        let mut source_vault = Vault::new();
        source_vault
            .insert(sample_entry("entry", 1_700_000_000))
            .expect("random source is available");
        let payload = Payload::from_vault(&master, id_b, &source_vault).expect("pack");
        let sealed = payload.seal(&master).expect("seal");
        let good_id = payload.sync_id;

        let mut broken = sealed.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0xFF;

        let ta = MemoryTransport::new(id_a, caps);
        ta.inject(id_b, broken);

        let mut seen_a = SeenSyncIds::new();
        let result = {
            let mut session_a = SyncSession::open(&master, &mut vault_a, &mut seen_a);
            session_a.receive(&ta)
        };
        assert!(result.is_err(), "a tampered payload must be rejected");
        assert_eq!(seen_a.len(), 0, "a rejected payload must not be recorded");
        assert!(
            !seen_a.contains(&good_id),
            "garbage poisoned the valid payload's id, so the real one is rejected forever"
        );

        ta.inject(id_b, sealed);
        let outcome = {
            let mut session_a = SyncSession::open(&master, &mut vault_a, &mut seen_a);
            session_a
                .receive(&ta)
                .expect("a valid payload must be accepted")
        };
        assert_eq!(outcome.merge.added, 1);
        assert_eq!(seen_a.len(), 1);
    }

    /// A payload that does not fit is reported **before** sending, with the bytes needed.
    #[test]
    fn a_payload_larger_than_the_channel_is_reported_before_sending() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, _) = a_device(2);
        for i in 0..40_u64 {
            vault_a
                .insert(sample_entry(&format!("entry {i}"), 1_700_000_000 + i))
                .expect("random source is available");
        }

        let caps = TransportCapabilities::qr(4, 64);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);

        let mut seen = SeenSyncIds::new();
        let session = SyncSession::open(&master, &mut vault_a, &mut seen);
        let result = session.send(&ta, Recipient::One(id_b), PayloadKind::Vault);

        match result {
            Err(Error::TransportMessageTooLarge { needed, limit }) => {
                assert_eq!(limit, 64);
                assert!(
                    needed > 64,
                    "the reported need {needed} must exceed the limit"
                );
            }
            other => panic!("expected a does-not-fit error, got {other:?}"),
        }

        assert!(
            ta.outbox.lock().expect("lock not poisoned").is_empty(),
            "nothing may be written to the channel when it does not fit"
        );
    }

    /// Two-party channels need no start signal; multi-party channels do.
    #[test]
    fn only_multi_party_channels_need_a_start_signal() {
        assert!(!TransportCapabilities::stream(Roster::TwoParty).needs_start_signal());
        assert!(TransportCapabilities::stream(Roster::MultiParty).needs_start_signal());
        assert!(!TransportCapabilities::qr(40, 2900).needs_start_signal());
        assert!(TransportCapabilities::qr(40, 2900).single_use);
        assert!(!TransportCapabilities::stream(Roster::TwoParty).single_use);
    }

    /// Multi-party session: after A broadcasts, B and C both receive the same content.
    #[test]
    fn a_multi_party_broadcast_reaches_every_peer() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);
        vault_a
            .insert(sample_entry("A's entry", 1_700_000_000))
            .expect("random source is available");

        let caps = TransportCapabilities::stream(Roster::MultiParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b, id_c]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a, id_c]);
        let tc = MemoryTransport::new(id_c, caps).with_peers(vec![id_a, id_b]);

        let mut seen_a = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::All, PayloadKind::Vault)
            .expect("broadcast");

        ta.deliver_to(&tb, true);
        ta.deliver_to(&tc, true);

        let mut seen_b = SeenSyncIds::new();
        let outcome_b = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("B receives");
        assert_eq!(outcome_b.merge.added, 1);

        let mut seen_c = SeenSyncIds::new();
        let outcome_c = SyncSession::open(&master, &mut vault_c, &mut seen_c)
            .receive(&tc)
            .expect("C receives");
        assert_eq!(outcome_c.merge.added, 1);

        assert_eq!(vault_b.len(), 1);
        assert_eq!(vault_c.len(), 1);
    }

    /// `Recipient::One` must really reach exactly one peer.
    ///
    /// The contract is upheld by implementations, so a test has to watch it: an
    /// implementation that delivers to everyone would turn a targeted send into a broadcast.
    #[test]
    fn a_targeted_send_does_not_reach_other_peers() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);
        vault_a
            .insert(sample_entry("only to B", 1_700_000_000))
            .expect("random source is available");

        let caps = TransportCapabilities::stream(Roster::MultiParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b, id_c]);
        let tb = MemoryTransport::new(id_b, caps);
        let tc = MemoryTransport::new(id_c, caps);

        let mut seen_a = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("targeted send");

        ta.deliver_to(&tc, true);
        assert!(
            tc.inbox.lock().expect("lock not poisoned").is_empty(),
            "a message addressed to B reached C"
        );

        ta.deliver_to(&tb, true);
        assert!(
            !tb.inbox.lock().expect("lock not poisoned").is_empty(),
            "it must reach B"
        );
        let _ = &mut vault_b;
        let _ = &mut vault_c;
    }

    /// "Already up to date" is a normal outcome, not an error.
    #[test]
    fn syncing_with_nothing_new_reports_no_change() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        vault_a
            .insert(sample_entry("the same one", 1_700_000_000))
            .expect("random source is available");

        let caps = TransportCapabilities::stream(Roster::TwoParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a]);

        let mut seen_a = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("send");
        ta.deliver_to(&tb, true);
        let mut seen_b = SeenSyncIds::new();
        let first = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("receive");
        assert_eq!(first.merge.added, 1);
        assert!(
            !first.made_no_change(),
            "the first round really did change something"
        );

        ta.clear_outbox();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("send");
        ta.deliver_to(&tb, true);
        let second = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("receive");

        assert!(
            second.made_no_change(),
            "identical content must report no change, got {second}"
        );
        assert!(!second.needs_adjudication());
    }

    /// Three devices converge after two sync rounds.
    ///
    /// The same byte sequence must converge to the same result no matter which channel
    /// carries it, which is what "three transports, one protocol" means.
    #[test]
    fn three_devices_converge_over_the_session() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);
        let (id_c, _, mut vault_c) = a_device(3);

        vault_a
            .insert(sample_entry("A", 1_700_000_000))
            .expect("random source is available");
        vault_b
            .insert(sample_entry("B", 1_700_000_100))
            .expect("random source is available");
        vault_c
            .insert(sample_entry("C", 1_700_000_200))
            .expect("random source is available");

        let caps = TransportCapabilities::stream(Roster::MultiParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b, id_c]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a, id_c]);
        let tc = MemoryTransport::new(id_c, caps).with_peers(vec![id_a, id_b]);

        let mut seen_a = SeenSyncIds::new();
        let mut seen_b = SeenSyncIds::new();
        let mut seen_c = SeenSyncIds::new();

        for _ in 0..2 {
            ta.clear_outbox();
            tb.clear_outbox();
            tc.clear_outbox();
            SyncSession::open(&master, &mut vault_a, &mut seen_a)
                .send(&ta, Recipient::All, PayloadKind::Vault)
                .expect("A broadcasts");
            SyncSession::open(&master, &mut vault_b, &mut seen_b)
                .send(&tb, Recipient::All, PayloadKind::Vault)
                .expect("B broadcasts");
            SyncSession::open(&master, &mut vault_c, &mut seen_c)
                .send(&tc, Recipient::All, PayloadKind::Vault)
                .expect("C broadcasts");

            ta.deliver_to(&tb, true);
            ta.deliver_to(&tc, true);
            tb.deliver_to(&ta, true);
            tb.deliver_to(&tc, true);
            tc.deliver_to(&ta, true);
            tc.deliver_to(&tb, true);

            for transport in [&ta, &tb, &tc] {
                loop {
                    let result = match transport.local_device() {
                        id if id == id_a => {
                            SyncSession::open(&master, &mut vault_a, &mut seen_a).receive(transport)
                        }
                        id if id == id_b => {
                            SyncSession::open(&master, &mut vault_b, &mut seen_b).receive(transport)
                        }
                        _ => {
                            SyncSession::open(&master, &mut vault_c, &mut seen_c).receive(transport)
                        }
                    };
                    match result {
                        Ok(_) => {}
                        Err(Error::SyncNoSessionFound) => break,
                        Err(other) => panic!("unexpected error: {other:?}"),
                    }
                }
            }
        }

        assert_eq!(vault_a.len(), 3, "A must have three records");
        assert_eq!(vault_b.len(), 3, "B must have three records");
        assert_eq!(vault_c.len(), 3, "C must have three records");
    }

    /// **Planning and sending must agree.**
    ///
    /// The whole point of planning is that the answer given before anything is displayed is
    /// correct, in both directions: planning and sending must use the same
    /// [`TransportCapabilities::check_fits`] test.
    #[test]
    fn planning_and_sending_agree() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, _) = a_device(2);
        vault_a
            .insert(sample_entry("entry", 1_700_000_000))
            .expect("random source is available");

        let roomy = MemoryTransport::new(id_a, TransportCapabilities::stream(Roster::TwoParty));
        let tiny = MemoryTransport::new(id_a, TransportCapabilities::qr(1, 8));

        let mut seen = SeenSyncIds::new();
        let session = SyncSession::open(&master, &mut vault_a, &mut seen);

        let len = match session.plan_share(&roomy).expect("plan") {
            SharePlan::FullPayload { len } => len,
            other => panic!("a roomy channel must not require a link: {other}"),
        };
        assert!(len > 0, "a payload with one entry cannot be empty");
        session
            .send(&roomy, Recipient::One(id_b), PayloadKind::Vault)
            .expect("planning said it fits, so sending must succeed");

        let plan = session.plan_share(&tiny).expect("plan");
        match plan {
            SharePlan::LinkEstablishment { needed, limit } => {
                assert_eq!(
                    limit, 8,
                    "the limit must come from the channel's declared capability"
                );
                assert_eq!(
                    needed, len,
                    "the two plans disagree on the size, so sealing is not length-deterministic"
                );
            }
            other => panic!("a channel that does not fit must require a link: {other}"),
        }
        let result = session.send(&tiny, Recipient::One(id_b), PayloadKind::Vault);
        let is_too_large = matches!(result, Err(Error::TransportMessageTooLarge { .. }));
        assert!(
            is_too_large,
            "planning said it does not fit, so sending must report the same: {result:?}"
        );
    }

    /// **The core library does not know about frames: the share decision depends only on
    /// the declared byte limit.**
    ///
    /// A multi-frame QR channel is indistinguishable here from a byte-stream channel that
    /// declares the same limit. Adding a frame count to [`TransportCapabilities`] and using
    /// it in [`TransportCapabilities::check_fits`] would make the two answers diverge.
    #[test]
    fn the_share_plan_depends_only_on_the_declared_byte_limit() {
        let (id_a, master, mut vault_a) = a_device(1);
        vault_a
            .insert(sample_entry("entry", 1_700_000_000))
            .expect("random source is available");

        let framed = MemoryTransport::new(id_a, TransportCapabilities::qr(40, 4096));
        let equivalent = MemoryTransport::new(
            id_a,
            TransportCapabilities {
                roster: Roster::MultiParty,
                max_message_len: Some(4096),
                max_qr_version: None,
                single_use: false,
                can_carry_payload: true,
            },
        );
        let tiny_framed = MemoryTransport::new(id_a, TransportCapabilities::qr(1, 8));
        let tiny_equivalent = MemoryTransport::new(
            id_a,
            TransportCapabilities {
                roster: Roster::TwoParty,
                max_message_len: Some(8),
                max_qr_version: None,
                single_use: false,
                can_carry_payload: true,
            },
        );

        let mut seen = SeenSyncIds::new();
        let session = SyncSession::open(&master, &mut vault_a, &mut seen);
        for (left, right, what) in [
            (&framed, &equivalent, "roomy"),
            (&tiny_framed, &tiny_equivalent, "tiny"),
        ] {
            let a = session.plan_share(left).expect("plan");
            let b = session.plan_share(right).expect("plan");
            assert_eq!(
                a, b,
                "{what} channel: the same limit must give the same answer (frames are irrelevant)"
            );
        }
    }

    /// A byte-stream channel has no limit, so link establishment never applies to it.
    ///
    /// If [`SharePlan`] reported "does not fit" for a byte stream, the QR-code guidance
    /// would show up on a LAN transfer and point the user at a route that does not exist
    /// there.
    #[test]
    fn a_stream_channel_never_needs_a_link() {
        let (id_a, master, mut vault_a) = a_device(1);
        for i in 0..64_u64 {
            vault_a
                .insert(sample_entry(&format!("entry {i}"), 1_700_000_000 + i))
                .expect("random source is available");
        }
        let transport =
            MemoryTransport::new(id_a, TransportCapabilities::stream(Roster::MultiParty));
        assert!(
            transport.capabilities().max_message_len.is_none(),
            "a byte-stream channel must have no per-message limit"
        );

        let mut seen = SeenSyncIds::new();
        let plan = SyncSession::open(&master, &mut vault_a, &mut seen)
            .plan_share(&transport)
            .expect("plan");
        assert!(
            !plan.needs_link(),
            "a byte-stream channel must not require a link: {plan}"
        );
    }

    /// An entry with an icon travels only over a channel **without** a message limit.
    ///
    /// A QR code cannot carry a 64 KiB picture (and a multi-frame code that "fits" only by
    /// dropping the icon would silently lose what the user sees). The refusal happens before
    /// anything is sealed and names the icon, so the user is not told "too large" for a payload
    /// whose real problem is a picture.
    #[test]
    fn a_limited_channel_refuses_entries_with_icons() {
        let (id_a, master, mut vault_a) = a_device(1);
        let icon =
            EntryIcon::new(IconMime::Png, vec![0x89, b'P', b'N', b'G']).expect("a small icon");
        vault_a
            .insert(sample_entry("with icon", 1_700_000_000).with_icon(Some(icon)))
            .expect("random source is available");

        let limited = MemoryTransport::new(id_a, TransportCapabilities::qr(40, 4096));
        let stream = MemoryTransport::new(id_a, TransportCapabilities::stream(Roster::TwoParty));
        let mut seen = SeenSyncIds::new();
        let session = SyncSession::open(&master, &mut vault_a, &mut seen);

        let sent = session.send(&limited, Recipient::All, PayloadKind::Vault);
        assert!(
            matches!(sent, Err(Error::SyncIconRequiresByteTransport)),
            "actual {sent:?}"
        );
        let planned = session.plan_share(&limited);
        assert!(
            matches!(planned, Err(Error::SyncIconRequiresByteTransport)),
            "planning must give the same answer before the user confirms: {planned:?}"
        );

        session
            .send(&stream, Recipient::All, PayloadKind::Vault)
            .expect("a byte-stream channel carries the icon");
    }

    /// **The first step of link establishment must actually work.**
    ///
    /// When the full state does not fit, the user is told to send a request first and move
    /// the data another way: **a channel that cannot carry the full state must still carry
    /// the request**.
    #[test]
    fn a_request_fits_where_the_full_state_does_not() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, _) = a_device(2);
        for i in 0..8_u64 {
            vault_a
                .insert(sample_entry(&format!("entry {i}"), 1_700_000_000 + i))
                .expect("random source is available");
        }

        let transport = MemoryTransport::new(id_a, TransportCapabilities::qr(10, 200));
        let mut seen = SeenSyncIds::new();
        let session = SyncSession::open(&master, &mut vault_a, &mut seen);

        let plan = session.plan_share(&transport).expect("plan");
        assert!(plan.needs_link(), "the full state must not fit: {plan}");

        session
            .send(&transport, Recipient::One(id_b), PayloadKind::Request)
            .expect("the request must fit, or link establishment cannot even start");
    }

    /// Conflicts are reported rather than silently resolved to one side.
    #[test]
    fn a_divergent_entry_is_reported_for_adjudication() {
        let (id_a, master, mut vault_a) = a_device(1);
        let (id_b, _, mut vault_b) = a_device(2);

        let shared = EntryId::from_bytes([9; EntryId::LEN]);
        vault_a
            .insert_with_id(shared, sample_entry("local version", 1_700_000_000))
            .expect("insert");
        vault_b
            .insert_with_id(shared, sample_entry("peer version", 1_700_000_500))
            .expect("insert");

        let caps = TransportCapabilities::stream(Roster::TwoParty);
        let ta = MemoryTransport::new(id_a, caps).with_peers(vec![id_b]);
        let tb = MemoryTransport::new(id_b, caps).with_peers(vec![id_a]);

        let mut seen_a = SeenSyncIds::new();
        SyncSession::open(&master, &mut vault_a, &mut seen_a)
            .send(&ta, Recipient::One(id_b), PayloadKind::Vault)
            .expect("send");
        ta.deliver_to(&tb, true);

        let mut seen_b = SeenSyncIds::new();
        let outcome = SyncSession::open(&master, &mut vault_b, &mut seen_b)
            .receive(&tb)
            .expect("receive");

        assert!(
            outcome.needs_adjudication(),
            "divergent content must be reported as a conflict, got {outcome}"
        );
        assert_eq!(outcome.merge.conflicts.len(), 1);
        assert_eq!(
            vault_b.get(&shared).expect("the entry is still there").name,
            "peer version",
            "a conflict must not silently overwrite local content"
        );
    }

    /// `RecordSet` / `merge_into` are usable without a session (for adjudication previews
    /// on the device side).
    #[test]
    fn the_merge_helpers_stay_usable_without_a_transport() {
        let (_, master, mut vault) = a_device(1);
        let mut source = VaultAlias::new();
        source
            .insert(sample_entry("from elsewhere", 1_700_000_000))
            .expect("random source is available");

        let payload =
            Payload::from_vault(&master, DeviceId::from_bytes([2; 32]), &source).expect("pack");
        let mut set = RecordSet::new();
        for record in payload.open_records(&master).expect("decrypt") {
            set.insert(record.into_merged());
        }
        let outcome = merge_into(&mut vault, &set).expect("merge");
        assert_eq!(outcome.added, 1);
        assert_eq!(vault.len(), 1);
    }
}
