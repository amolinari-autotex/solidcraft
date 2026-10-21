//! Bounded, in-memory connector enrollment. This is not a login or transport.
//! Administration requires an opaque capability minted by authenticated Store access.
//! Connector grants convey tunnel identity only, never document or user privileges.
use crate::{AuthToken, Error, digest};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const MAX_PENDING: usize = 16;
const MAX_CONNECTORS: usize = 256;
const MAX_ATTEMPTS: u8 = 5;
const MAX_LIFETIME: Duration = Duration::from_secs(300);

pub struct PairingSecret(String);
pub struct ConnectorSecret(String);

macro_rules! secret {
    ($name:ident) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
        impl $name {
            /// Transfer directly to private transport/keyring storage; never log.
            pub fn into_bearer(self) -> String {
                self.0
            }
        }
    };
}
secret!(PairingSecret);
secret!(ConnectorSecret);

#[derive(Debug, PartialEq, Eq)]
pub struct PairingReceipt {
    pub challenge_id: String,
    pub server_id: String,
    pub tunnel_id: String,
    pub expires_in: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorIdentity {
    pub connector_id: String,
    pub server_id: String,
    pub tunnel_id: String,
}

#[derive(Debug)]
pub struct ConnectorGrant {
    pub identity: ConnectorIdentity,
    pub secret: ConnectorSecret,
}

struct Pending {
    server_id: String,
    tunnel_id: String,
    secret_hash: String,
    expires: Instant,
    attempts: u8,
}

struct Enrolled {
    identity: ConnectorIdentity,
    token_hash: String,
}

/// Serialize access through one gateway owner or a mutex. `&mut self` makes
/// redemption single-use atomically within that owner. State is not persistent:
/// restart invalidates every challenge and connector token; no admin is created.
#[derive(Default)]
pub struct PairingRegistry {
    pending: BTreeMap<String, Pending>,
    enrolled: BTreeMap<String, Enrolled>,
}

/// Store-minted authorization bound to the actual authenticated server.
/// No public constructor, deserialization or cloning is available.
#[derive(Debug)]
pub struct PairingAdmin {
    principal_id: String,
    server_id: String,
}

impl PairingAdmin {
    /// Only the configured-principal authentication path may mint this capability.
    /// The legacy loopback owner credential must never be accepted here.
    pub(crate) fn authenticated(principal_id: String, server_id: String) -> Self {
        Self { principal_id, server_id }
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }
}

fn server_id_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl PairingRegistry {
    pub fn issue(&mut self, admin: &PairingAdmin, tunnel_id: &str, lifetime: Duration) -> Result<(PairingReceipt, PairingSecret), Error> {
        self.issue_at(admin, tunnel_id, lifetime, Instant::now())
    }

    fn issue_at(
        &mut self,
        admin: &PairingAdmin,
        tunnel_id: &str,
        lifetime: Duration,
        now: Instant,
    ) -> Result<(PairingReceipt, PairingSecret), Error> {
        let server_id = admin.server_id.as_str();
        if !server_id_valid(server_id) || !crate::valid_id(tunnel_id) || lifetime.is_zero() || lifetime > MAX_LIFETIME {
            return Err(Error::Invalid("connector pairing parameters"));
        }
        self.pending.retain(|_, pending| pending.expires > now);
        if self.enrolled.contains_key(tunnel_id) || self.pending.values().any(|pending| pending.tunnel_id == tunnel_id) {
            return Err(Error::Conflict);
        }
        if self.pending.len() >= MAX_PENDING || self.enrolled.len() >= MAX_CONNECTORS {
            return Err(Error::Invalid("connector pairing capacity"));
        }
        let expires = now.checked_add(lifetime).ok_or(Error::Invalid("connector pairing expiry"))?;
        let challenge_id = AuthToken::generate()?;
        if self.pending.contains_key(&challenge_id) {
            return Err(Error::Conflict);
        }
        let secret = PairingSecret(AuthToken::generate()?);
        self.pending.insert(
            challenge_id.clone(),
            Pending { server_id: server_id.into(), tunnel_id: tunnel_id.into(), secret_hash: digest(secret.0.as_bytes()), expires, attempts: 0 },
        );
        Ok((PairingReceipt { challenge_id, server_id: server_id.into(), tunnel_id: tunnel_id.into(), expires_in: lifetime }, secret))
    }

    pub fn redeem(&mut self, challenge_id: &str, server_id: &str, secret: &str) -> Result<ConnectorGrant, Error> {
        self.redeem_at(challenge_id, server_id, secret, Instant::now())
    }

    fn redeem_at(&mut self, challenge_id: &str, server_id: &str, secret: &str, now: Instant) -> Result<ConnectorGrant, Error> {
        let pending = self.pending.get_mut(challenge_id).ok_or(Error::Forbidden)?;
        let valid = secret.len() == 64 && bool::from(digest(secret.as_bytes()).as_bytes().ct_eq(pending.secret_hash.as_bytes()));
        if now >= pending.expires {
            self.pending.remove(challenge_id);
            return Err(Error::Forbidden);
        }
        if !valid || server_id != pending.server_id {
            pending.attempts += 1;
            if pending.attempts >= MAX_ATTEMPTS {
                self.pending.remove(challenge_id);
            }
            return Err(Error::Forbidden);
        }
        // Generate before consuming the challenge: entropy failure permits a retry.
        let connector_id = AuthToken::generate()?;
        let secret = ConnectorSecret(AuthToken::generate()?);
        let pending = self.pending.remove(challenge_id).ok_or(Error::Forbidden)?;
        if self.enrolled.contains_key(&pending.tunnel_id) || self.enrolled.len() >= MAX_CONNECTORS {
            return Err(Error::Conflict);
        }
        let identity = ConnectorIdentity { connector_id, server_id: pending.server_id, tunnel_id: pending.tunnel_id };
        self.enrolled.insert(identity.tunnel_id.clone(), Enrolled { identity: identity.clone(), token_hash: digest(secret.0.as_bytes()) });
        Ok(ConnectorGrant { identity, secret })
    }

    pub fn revoke_challenge(&mut self, admin: &PairingAdmin, challenge_id: &str) -> Result<(), Error> {
        let pending = self.pending.get(challenge_id).ok_or(Error::NotFound)?;
        if pending.server_id != admin.server_id {
            return Err(Error::Forbidden);
        }
        self.pending.remove(challenge_id).ok_or(Error::NotFound)?;
        Ok(())
    }

    /// Administrative revocation invalidates the enrolled token and every pending
    /// challenge for this tunnel. Reenrollment must issue fresh credentials.
    pub fn revoke_connector(&mut self, admin: &PairingAdmin, tunnel_id: &str) -> Result<(), Error> {
        if !crate::valid_id(tunnel_id) {
            return Err(Error::Invalid("connector tunnel ID"));
        }
        if self.enrolled.get(tunnel_id).is_some_and(|entry| entry.identity.server_id != admin.server_id)
            || self.pending.values().any(|pending| pending.tunnel_id == tunnel_id && pending.server_id != admin.server_id)
        {
            return Err(Error::Forbidden);
        }
        let enrolled = self.enrolled.remove(tunnel_id).is_some();
        let previous_pending = self.pending.len();
        self.pending.retain(|_, pending| pending.tunnel_id != tunnel_id);
        if !enrolled && previous_pending == self.pending.len() {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Returns tunnel-only identity; never convert this into a user principal.
    pub fn authenticate_connector(&self, tunnel_id: &str, token: &str) -> Option<ConnectorIdentity> {
        if token.len() != 64 {
            return None;
        }
        let enrolled = self.enrolled.get(tunnel_id)?;
        bool::from(digest(token.as_bytes()).as_bytes().ct_eq(enrolled.token_hash.as_bytes())).then(|| enrolled.identity.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn admin() -> PairingAdmin {
        PairingAdmin::authenticated("admin".into(), server())
    }
    fn server() -> String {
        "a".repeat(64)
    }

    #[test]
    fn single_use_and_separate_connector_authority() -> Result<(), Error> {
        let mut registry = PairingRegistry::default();
        let (receipt, secret) = registry.issue(&admin(), "tunnel", MAX_LIFETIME)?;
        let bearer = secret.into_bearer();
        let grant = registry.redeem(&receipt.challenge_id, &server(), &bearer)?;
        assert_eq!(grant.identity.tunnel_id, "tunnel");
        let identity = grant.identity;
        let connector_token = grant.secret.into_bearer();
        assert_ne!(connector_token, bearer);
        assert_eq!(registry.authenticate_connector("tunnel", &connector_token), Some(identity));
        assert_eq!(registry.authenticate_connector("tunnel", &bearer), None);
        assert!(registry.redeem(&receipt.challenge_id, &server(), &bearer).is_err());
        assert!(registry.issue(&admin(), "tunnel", MAX_LIFETIME).is_err());
        Ok(())
    }

    #[test]
    fn expiry_and_revocation() -> Result<(), Error> {
        let now = Instant::now();
        let mut registry = PairingRegistry::default();
        let (receipt, secret) = registry.issue_at(&admin(), "tunnel", MAX_LIFETIME, now)?;
        assert!(registry.redeem_at(&receipt.challenge_id, &server(), &secret.into_bearer(), now + MAX_LIFETIME).is_err());
        let (receipt, secret) = registry.issue_at(&admin(), "tunnel", MAX_LIFETIME, now)?;
        registry.revoke_challenge(&admin(), &receipt.challenge_id)?;
        assert!(registry.redeem_at(&receipt.challenge_id, &server(), &secret.into_bearer(), now).is_err());
        Ok(())
    }

    #[test]
    fn wrong_server_and_secret_exhaust_attempts() -> Result<(), Error> {
        let now = Instant::now();
        let mut registry = PairingRegistry::default();
        let (receipt, secret) = registry.issue_at(&admin(), "tunnel", MAX_LIFETIME, now)?;
        let bearer = secret.into_bearer();
        for _ in 0..4 {
            assert!(registry.redeem_at(&receipt.challenge_id, &"b".repeat(64), &bearer, now).is_err());
        }
        assert!(registry.redeem_at(&receipt.challenge_id, &server(), "wrong", now).is_err());
        assert!(registry.redeem_at(&receipt.challenge_id, &server(), &bearer, now).is_err());
        assert!(registry.pending.is_empty());
        Ok(())
    }

    #[test]
    fn capability_capacity_and_validation() -> Result<(), Error> {
        let now = Instant::now();
        let mut registry = PairingRegistry::default();
        for lifetime in [Duration::ZERO, MAX_LIFETIME + Duration::from_secs(1)] {
            assert!(registry.issue_at(&admin(), "tunnel", lifetime, now).is_err());
        }
        assert!(registry.issue_at(&PairingAdmin::authenticated("admin".into(), "bad".into()), "tunnel", MAX_LIFETIME, now).is_err());
        assert!(registry.issue_at(&admin(), "../bad", MAX_LIFETIME, now).is_err());
        for index in 0..MAX_PENDING {
            registry.issue_at(&admin(), &format!("tunnel-{index}"), MAX_LIFETIME, now)?;
        }
        assert!(registry.issue_at(&admin(), "overflow", MAX_LIFETIME, now).is_err());
        assert!(registry.issue_at(&admin(), "after-expiry", MAX_LIFETIME, now + MAX_LIFETIME).is_ok());
        Ok(())
    }

    #[test]
    fn debug_never_exposes_secrets_or_registry() {
        let pairing = PairingSecret("sensitive-pairing".into());
        let connector = ConnectorSecret("sensitive-connector".into());
        assert_eq!(format!("{pairing:?}"), "PairingSecret([redacted])");
        assert_eq!(format!("{connector:?}"), "ConnectorSecret([redacted])");
        let grant = ConnectorGrant {
            identity: ConnectorIdentity { connector_id: "public".into(), server_id: server(), tunnel_id: "tunnel".into() },
            secret: connector,
        };
        assert!(!format!("{grant:?}").contains("sensitive"));
    }

    #[test]
    fn administrator_revokes_connector_and_reenrollment_is_fresh() -> Result<(), Error> {
        let mut registry = PairingRegistry::default();
        let (receipt, pairing) = registry.issue(&admin(), "tunnel", MAX_LIFETIME)?;
        let original = registry.redeem(&receipt.challenge_id, &server(), &pairing.into_bearer())?;
        let original_identity = original.identity;
        let original_token = original.secret.into_bearer();
        let other_server = PairingAdmin::authenticated("other-admin".into(), "b".repeat(64));
        assert!(registry.revoke_connector(&other_server, "tunnel").is_err());
        assert_eq!(registry.authenticate_connector("tunnel", &original_token), Some(original_identity.clone()));
        registry.revoke_connector(&admin(), "tunnel")?;
        assert_eq!(registry.authenticate_connector("tunnel", &original_token), None);
        let (receipt, pairing) = registry.issue(&admin(), "tunnel", MAX_LIFETIME)?;
        let replacement = registry.redeem(&receipt.challenge_id, &server(), &pairing.into_bearer())?;
        let replacement_identity = replacement.identity;
        let replacement_token = replacement.secret.into_bearer();
        assert_ne!(original_token, replacement_token);
        assert_ne!(original_identity.connector_id, replacement_identity.connector_id);
        assert_eq!(registry.authenticate_connector("tunnel", &original_token), None);
        assert_eq!(registry.authenticate_connector("tunnel", &replacement_token), Some(replacement_identity));
        let (pending, pending_secret) = registry.issue(&admin(), "pending-tunnel", MAX_LIFETIME)?;
        registry.revoke_connector(&admin(), "pending-tunnel")?;
        assert!(registry.redeem(&pending.challenge_id, &server(), &pending_secret.into_bearer()).is_err());
        assert!(registry.issue(&admin(), "pending-tunnel", MAX_LIFETIME).is_ok());
        assert!(registry.revoke_connector(&admin(), "unknown").is_err());
        Ok(())
    }

    #[test]
    fn opaque_administration_is_bound_to_its_authenticated_server() -> Result<(), Error> {
        let mut registry = PairingRegistry::default();
        let server_a = admin();
        let server_b = PairingAdmin::authenticated("admin-b".into(), "b".repeat(64));
        assert_eq!(server_a.principal_id(), "admin");
        let (receipt_a, secret_a) = registry.issue(&server_a, "tunnel-a", MAX_LIFETIME)?;
        let (receipt_b, secret_b) = registry.issue(&server_b, "tunnel-b", MAX_LIFETIME)?;
        assert_eq!(receipt_a.server_id, server());
        assert_eq!(receipt_b.server_id, "b".repeat(64));
        assert!(matches!(registry.revoke_challenge(&server_a, &receipt_b.challenge_id), Err(Error::Forbidden)));
        assert!(matches!(registry.revoke_connector(&server_a, "tunnel-b"), Err(Error::Forbidden)));
        assert!(matches!(registry.revoke_challenge(&server_b, &receipt_a.challenge_id), Err(Error::Forbidden)));
        let grant_b = registry.redeem(&receipt_b.challenge_id, &receipt_b.server_id, &secret_b.into_bearer())?;
        let token_b = grant_b.secret.into_bearer();
        assert!(matches!(registry.revoke_connector(&server_a, "tunnel-b"), Err(Error::Forbidden)));
        assert_eq!(registry.authenticate_connector("tunnel-b", &token_b), Some(grant_b.identity));
        registry.revoke_challenge(&server_a, &receipt_a.challenge_id)?;
        assert!(registry.redeem(&receipt_a.challenge_id, &receipt_a.server_id, &secret_a.into_bearer()).is_err());
        registry.revoke_connector(&server_b, "tunnel-b")?;
        assert_eq!(registry.authenticate_connector("tunnel-b", &token_b), None);
        Ok(())
    }
}
