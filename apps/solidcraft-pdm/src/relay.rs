//! Transient, bounded relay exchange; this module grants no document authority.
//!
//! A trusted relay operator can see forwarded user bearer credentials in memory.
//! Future transports must use TLS; this is not end-to-end encryption. Connector
//! capabilities authenticate one tunnel, separately from the forwarded user.
//! Restart/cancellation loses delivery, never releases a domain checkout. Clients
//! reconcile ambiguous writes using authoritative operation receipts.
use crate::{AuthToken, Error, MAX_FRAME, Request, Response, digest};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const CAPACITY: usize = 16;
const MAX_TTL: Duration = Duration::from_secs(60);
const MAX_POLL: Duration = Duration::from_secs(5);

pub struct TunnelConfig {
    id: String,
    server_id: String,
    connector_sha256: String,
}
impl TunnelConfig {
    pub fn new(id: &str, server_id: &str, connector_sha256: &str) -> Result<Self, Error> {
        if id.is_empty()
            || id.len() > 64
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || connector_sha256.len() != 64
            || !connector_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || server_id.len() != 64
            || !server_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Invalid("relay tunnel configuration"));
        }
        Ok(Self { id: id.into(), server_id: server_id.to_ascii_lowercase(), connector_sha256: connector_sha256.to_ascii_lowercase() })
    }
}

struct Slot {
    tunnel: String,
    expires: Instant,
    input: Option<(AuthToken, Request)>,
    lease: Option<String>,
    response: Option<Response>,
}
#[derive(Default)]
struct State {
    slots: BTreeMap<String, Slot>,
    queue: VecDeque<String>,
}
impl State {
    fn prune(&mut self) {
        let now = Instant::now();
        self.slots.retain(|_, slot| slot.expires > now);
        self.queue.retain(|id| self.slots.contains_key(id));
    }
}
struct Shared {
    tunnels: BTreeMap<String, (String, String)>,
    state: Mutex<State>,
    changed: Condvar,
}
#[derive(Clone)]
pub struct Relay {
    shared: Arc<Shared>,
}
impl Relay {
    pub fn new(configs: Vec<TunnelConfig>) -> Result<Self, Error> {
        if configs.is_empty() || configs.len() > CAPACITY {
            return Err(Error::Invalid("relay tunnel count"));
        }
        let mut tunnels = BTreeMap::new();
        let mut capabilities = std::collections::BTreeSet::new();
        for config in configs {
            if !capabilities.insert(config.connector_sha256.clone()) {
                return Err(Error::Invalid("duplicate relay connector capability"));
            }
            if tunnels.insert(config.id, (config.server_id, config.connector_sha256)).is_some() {
                return Err(Error::Invalid("duplicate relay tunnel"));
            }
        }
        Ok(Self { shared: Arc::new(Shared { tunnels, state: Mutex::new(State::default()), changed: Condvar::new() }) })
    }
    fn state(&self) -> Result<MutexGuard<'_, State>, Error> {
        self.shared.state.lock().map_err(|_| Error::Invalid("relay unavailable"))
    }
    pub fn server_id(&self, tunnel: &str) -> Result<&str, Error> {
        self.shared.tunnels.get(tunnel).map(|(server_id, _)| server_id.as_str()).ok_or(Error::NotFound)
    }
    fn authorize(&self, tunnel: &str, token: &AuthToken) -> Result<(), Error> {
        let supplied = digest(token.0.as_bytes());
        if !self.shared.tunnels.get(tunnel).is_some_and(|(_, hash)| bool::from(hash.as_bytes().ct_eq(supplied.as_bytes()))) {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub fn submit(&self, tunnel: &str, credential: AuthToken, request: Request, ttl: Duration) -> Result<Pending, Error> {
        if !self.shared.tunnels.contains_key(tunnel) {
            return Err(Error::NotFound);
        }
        if ttl.is_zero() || ttl > MAX_TTL || serde_json::to_vec(&request)?.len() > MAX_FRAME as usize {
            return Err(Error::Invalid("relay request limits"));
        }
        let id = AuthToken::generate()?;
        let mut state = self.state()?;
        state.prune();
        if state.slots.len() >= CAPACITY {
            return Err(Error::Invalid("relay capacity"));
        }
        if state.slots.contains_key(&id) {
            return Err(Error::Invalid("relay identifier collision"));
        }
        state.slots.insert(
            id.clone(),
            Slot { tunnel: tunnel.into(), expires: Instant::now() + ttl, input: Some((credential, request)), lease: None, response: None },
        );
        state.queue.push_back(id.clone());
        self.shared.changed.notify_all();
        Ok(Pending { relay: self.clone(), id })
    }
    pub fn poll(&self, tunnel: &str, connector: &AuthToken, timeout: Duration) -> Result<Option<ForwardJob>, Error> {
        self.authorize(tunnel, connector)?;
        if timeout > MAX_POLL {
            return Err(Error::Invalid("relay poll timeout"));
        }
        let until = Instant::now() + timeout;
        let mut state = self.state()?;
        loop {
            state.prune();
            if let Some(index) = state.queue.iter().position(|id| state.slots.get(id).is_some_and(|slot| slot.tunnel == tunnel)) {
                // Entropy failure must leave the queued request available.
                let lease = AuthToken::generate()?;
                let id = state.queue.remove(index).ok_or(Error::Integrity)?;
                let slot = state.slots.get_mut(&id).ok_or(Error::Integrity)?;
                let (credential, request) = slot.input.take().ok_or(Error::Integrity)?;
                slot.lease = Some(lease.clone());
                return Ok(Some(ForwardJob { id, lease, credential, request }));
            }
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            state = self.shared.changed.wait_timeout(state, remaining).map_err(|_| Error::Invalid("relay unavailable"))?.0;
        }
    }
    pub fn complete(&self, tunnel: &str, connector: &AuthToken, id: &str, lease: &str, response: Response) -> Result<(), Error> {
        self.authorize(tunnel, connector)?;
        if id.len() != 64 || lease.len() != 64 || serde_json::to_vec(&response)?.len() > MAX_FRAME as usize {
            return Err(Error::Invalid("relay response limits"));
        }
        let mut state = self.state()?;
        state.prune();
        let slot = state.slots.get_mut(id).ok_or(Error::NotFound)?;
        if slot.tunnel != tunnel
            || slot.response.is_some()
            || !slot.lease.as_ref().is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(lease.as_bytes())))
        {
            return Err(Error::Forbidden);
        }
        slot.response = Some(response);
        self.shared.changed.notify_all();
        Ok(())
    }
}

/// Not serializable: a future connector transport must place the user credential
/// in a protected authorization header rather than a command or status payload.
pub struct ForwardJob {
    id: String,
    lease: String,
    credential: AuthToken,
    request: Request,
}
impl ForwardJob {
    pub(crate) fn from_parts(id: String, lease: String, credential: AuthToken, request: Request) -> Result<Self, Error> {
        if [&id, &lease].iter().any(|value| value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()))
            || serde_json::to_vec(&request)?.len() > MAX_FRAME as usize
        {
            return Err(Error::Invalid("forwarded relay job limits"));
        }
        Ok(Self { id, lease, credential, request })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn lease(&self) -> &str {
        &self.lease
    }
    pub fn credential(&self) -> &AuthToken {
        &self.credential
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn into_parts(self) -> (String, String, AuthToken, Request) {
        (self.id, self.lease, self.credential, self.request)
    }
}
impl std::fmt::Debug for ForwardJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ForwardJob([redacted])")
    }
}
pub struct Pending {
    relay: Relay,
    id: String,
}
impl Pending {
    pub fn cancel(&self) -> Result<(), Error> {
        let mut state = self.relay.state()?;
        state.slots.remove(&self.id);
        state.queue.retain(|id| id != &self.id);
        self.relay.shared.changed.notify_all();
        Ok(())
    }
    pub fn wait(self, timeout: Duration) -> Result<Response, Error> {
        if timeout > MAX_TTL {
            return Err(Error::Invalid("relay wait timeout"));
        }
        let until = Instant::now() + timeout;
        let mut state = self.relay.state()?;
        loop {
            state.prune();
            let slot = state.slots.get_mut(&self.id).ok_or(Error::NotFound)?;
            if let Some(response) = slot.response.take() {
                state.slots.remove(&self.id);
                return Ok(response);
            }
            let remaining = until.min(slot.expires).saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Invalid("relay response timeout"));
            }
            state = self.relay.shared.changed.wait_timeout(state, remaining).map_err(|_| Error::Invalid("relay unavailable"))?.0;
        }
    }
}
impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pending([redacted])")
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn token(byte: &str) -> AuthToken {
        AuthToken::parse(byte.repeat(64)).unwrap()
    }
    fn relay() -> Relay {
        Relay::new(vec![
            TunnelConfig::new("a", &"1".repeat(64), &digest(token("a").0.as_bytes())).unwrap(),
            TunnelConfig::new("b", &"2".repeat(64), &digest(token("b").0.as_bytes())).unwrap(),
        ])
        .unwrap()
    }
    fn submit(relay: &Relay) -> Pending {
        relay.submit("a", token("c"), Request::ManagedCatalog, Duration::from_secs(1)).unwrap()
    }
    fn response() -> Response {
        Response::Error { code: "not_found".into() }
    }
    #[test]
    fn duplicate_capabilities_and_untrusted_forwarded_fields_are_rejected() {
        let hash = digest(token("a").0.as_bytes());
        assert!(
            Relay::new(vec![
                TunnelConfig::new("a", &"1".repeat(64), &hash).unwrap(),
                TunnelConfig::new("b", &"2".repeat(64), &hash.to_ascii_uppercase()).unwrap()
            ])
            .is_err()
        );
        assert!(ForwardJob::from_parts("x".repeat(64), "a".repeat(64), token("c"), Request::ManagedCatalog).is_err());
        assert!(ForwardJob::from_parts("a".repeat(64), "a".repeat(63), token("c"), Request::ManagedCatalog).is_err());
        assert!(
            ForwardJob::from_parts(
                "a".repeat(64),
                "b".repeat(64),
                token("c"),
                Request::ManagedCreate { logical_path: "x".repeat(MAX_FRAME as usize) }
            )
            .is_err()
        );
        let job = ForwardJob::from_parts("a".repeat(64), "b".repeat(64), token("c"), Request::ManagedCatalog).unwrap();
        assert!(!format!("{job:?}").contains(&token("c").0));
    }
    #[test]
    fn capabilities_and_lease_fence_delivery() {
        let relay = relay();
        let pending = submit(&relay);
        assert!(relay.poll("a", &token("b"), Duration::ZERO).is_err());
        assert!(relay.poll("b", &token("b"), Duration::ZERO).unwrap().is_none());
        let job = relay.poll("a", &token("a"), Duration::ZERO).unwrap().unwrap();
        assert!(!format!("{job:?} {pending:?}").contains(&token("c").0));
        assert!(!format!("{job:?}").contains(job.lease()));
        assert!(relay.complete("a", &token("b"), job.id(), job.lease(), response()).is_err());
        assert!(relay.complete("b", &token("b"), job.id(), job.lease(), response()).is_err());
        assert!(relay.complete("a", &token("a"), job.id(), &"f".repeat(64), response()).is_err());
        relay.complete("a", &token("a"), job.id(), job.lease(), response()).unwrap();
        assert!(relay.complete("a", &token("a"), job.id(), job.lease(), response()).is_err());
        assert!(matches!(pending.wait(Duration::ZERO).unwrap(),Response::Error{code} if code=="not_found"));
        assert!(relay.complete("a", &token("a"), job.id(), job.lease(), response()).is_err());
    }
    #[test]
    fn capacity_is_shared_and_cancel_releases_queued_and_leased_slots() {
        let relay = relay();
        let mut pending: Vec<_> = (0..CAPACITY).map(|_| submit(&relay)).collect();
        assert!(relay.submit("b", token("c"), Request::ManagedCatalog, Duration::from_secs(1)).is_err());
        let job = relay.poll("a", &token("a"), Duration::ZERO).unwrap().unwrap();
        pending.remove(0).cancel().unwrap();
        assert!(relay.complete("a", &token("a"), job.id(), job.lease(), response()).is_err());
        let replacement = submit(&relay);
        drop(replacement);
        drop(pending);
        assert!(relay.poll("a", &token("a"), Duration::ZERO).unwrap().is_none());
        assert_eq!(relay.state().unwrap().slots.len(), 0);
    }
    #[test]
    fn expiry_and_wait_timeout_reclaim_capacity() {
        let relay = relay();
        let pending = relay.submit("a", token("c"), Request::ManagedCatalog, Duration::from_millis(10)).unwrap();
        let job = relay.poll("a", &token("a"), Duration::ZERO).unwrap().unwrap();
        assert!(pending.wait(Duration::from_millis(40)).is_err());
        assert!(relay.complete("a", &token("a"), job.id(), job.lease(), response()).is_err());
        assert!(submit(&relay).wait(Duration::ZERO).is_err());
        assert_eq!(relay.state().unwrap().slots.len(), 0);
    }
    #[test]
    fn frame_and_time_limits_are_enforced_before_delivery() {
        let relay = relay();
        assert!(relay.submit("a", token("c"), Request::ManagedCatalog, Duration::ZERO).is_err());
        assert!(relay.submit("a", token("c"), Request::ManagedCatalog, MAX_TTL + Duration::from_secs(1)).is_err());
        assert!(
            relay.submit("a", token("c"), Request::ManagedCreate { logical_path: "x".repeat(MAX_FRAME as usize) }, Duration::from_secs(1)).is_err()
        );
        let pending = submit(&relay);
        let job = relay.poll("a", &token("a"), Duration::ZERO).unwrap().unwrap();
        assert!(relay.complete("a", &token("a"), job.id(), job.lease(), Response::Error { code: "x".repeat(MAX_FRAME as usize) }).is_err());
        relay.complete("a", &token("a"), job.id(), job.lease(), response()).unwrap();
        assert!(pending.wait(Duration::ZERO).is_ok());
    }
    #[test]
    fn cancellation_wins_against_late_connector_completion() {
        let relay = relay();
        let pending = submit(&relay);
        let job = relay.poll("a", &token("a"), Duration::ZERO).unwrap().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let thread_barrier = barrier.clone();
        let thread_relay = relay.clone();
        let worker = std::thread::spawn(move || {
            thread_barrier.wait();
            thread_relay.complete("a", &token("a"), job.id(), job.lease(), response())
        });
        pending.cancel().unwrap();
        barrier.wait();
        assert!(worker.join().unwrap().is_err());
        assert!(pending.wait(Duration::ZERO).is_err());
    }
}
