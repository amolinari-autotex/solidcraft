use super::*;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceCapabilities {
    pub protocol: String,
    pub server_id: String,
    pub principal: Principal,
    pub supported: bool,
    pub can_mutate: bool,
    pub stable_materialization_paths: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceMetadata {
    pub entry: CatalogEntry,
    pub materialization_path: String,
    pub revision: u64,
    pub tombstoned: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NamespaceAction {
    Rename { logical_path: String },
    Tombstone,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceMutation {
    pub document: String,
    pub request_id: String,
    pub expected_head: Option<u64>,
    pub expected_revision: u64,
    pub action: NamespaceAction,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceReceipt {
    owner: String,
    fingerprint: String,
    result: NamespaceMetadata,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NamespaceState {
    pub(super) last_document: String,
    materialization_paths: BTreeMap<String, String>,
    revisions: BTreeMap<String, u64>,
    deleted: BTreeSet<String>,
    receipts: BTreeMap<String, NamespaceReceipt>,
}
impl NamespaceState {
    pub(super) fn tombstoned(&self, id: &str) -> bool {
        self.deleted.contains(id)
    }
    pub(super) fn validate(&self, state: &State) -> Result<(), Error> {
        if !state.documents.contains_key(&self.last_document)
            || self.receipts.len() > 256
            || self.revisions.iter().any(|(id, rev)| *rev == 0 || !state.documents.contains_key(id))
            || self.revisions.keys().any(|id| !self.materialization_paths.contains_key(id))
            || self.materialization_paths.iter().any(|(id, path)| !state.documents.contains_key(id) || validate_logical_path(path).is_err())
            || self.deleted.iter().any(|id| !self.revisions.contains_key(id) || state.documents.get(id).is_none_or(|e| e.checkout.is_some()))
            || self.receipts.iter().any(|(id, r)| {
                !crate::valid_id(id)
                    || !label(&r.owner)
                    || !hash_id(&r.fingerprint)
                    || !state.documents.contains_key(&r.result.entry.document)
                    || self.materialization_paths.get(&r.result.entry.document) != Some(&r.result.materialization_path)
            })
        {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}
impl ManagedStore {
    pub(crate) fn namespace_capabilities(&self, principal: &Principal) -> NamespaceCapabilities {
        let supported = self.metadata.is_some();
        NamespaceCapabilities {
            protocol: NAMESPACE_PROTOCOL.into(),
            server_id: self.state.server_id.clone(),
            principal: principal.clone(),
            supported,
            can_mutate: supported && principal.role != Role::Viewer,
            stable_materialization_paths: supported,
        }
    }
    pub(crate) fn tombstoned(&self, id: &str) -> bool {
        self.state.namespace.as_ref().is_some_and(|n| n.tombstoned(id))
    }
    pub(super) fn materialization_path(&self, entry: &CatalogEntry) -> String {
        self.state
            .namespace
            .as_ref()
            .and_then(|n| n.materialization_paths.get(&entry.document))
            .cloned()
            .unwrap_or_else(|| entry.logical_path.clone())
    }
    pub(super) fn legacy_entry(&self, entry: &CatalogEntry) -> CatalogEntry {
        let mut compatible = entry.clone();
        compatible.logical_path = self.materialization_path(entry);
        compatible
    }
    pub(super) fn namespace_path_conflict(&self, path: &str, except: Option<&str>) -> bool {
        self.namespace_path_conflict_inner(path, except, true)
    }
    fn namespace_path_conflict_inner(&self, path: &str, except: Option<&str>, reserve_tombstones: bool) -> bool {
        fn overlaps(a: &str, b: &str) -> bool {
            let a = a.to_lowercase();
            let b = b.to_lowercase();
            a == b || a.strip_prefix(&b).is_some_and(|tail| tail.starts_with('/')) || b.strip_prefix(&a).is_some_and(|tail| tail.starts_with('/'))
        }
        self.state.documents.values().any(|entry| {
            Some(entry.document.as_str()) != except
                && (reserve_tombstones || !self.tombstoned(&entry.document))
                && (overlaps(&entry.logical_path, path) || overlaps(&self.materialization_path(entry), path))
        })
    }
    pub(crate) fn namespace_catalog(&self) -> Result<Vec<NamespaceMetadata>, Error> {
        if self.metadata.is_none() {
            return Err(Error::Invalid("namespace operations require transactional metadata"));
        }
        self.state.documents.keys().filter(|id| !self.tombstoned(id)).map(|id| self.namespace_metadata(id)).collect()
    }
    pub(crate) fn namespace_metadata(&self, id: &str) -> Result<NamespaceMetadata, Error> {
        if self.metadata.is_none() {
            return Err(Error::Invalid("namespace operations require transactional metadata"));
        }
        let entry = self.state.documents.get(id).ok_or(Error::NotFound)?.clone();
        Ok(NamespaceMetadata {
            materialization_path: self.materialization_path(&entry),
            entry,
            revision: self.state.namespace.as_ref().and_then(|n| n.revisions.get(id)).copied().unwrap_or(0),
            tombstoned: self.tombstoned(id),
        })
    }
    pub(crate) fn namespace_mutate(&mut self, principal: &Principal, input: NamespaceMutation, referenced: bool) -> Result<NamespaceMetadata, Error> {
        Self::write_permission(principal)?;
        if !crate::valid_id(&input.request_id) {
            return Err(Error::Invalid("namespace request id"));
        }
        let current = self.namespace_metadata(&input.document)?;
        let fingerprint = digest(&serde_json::to_vec(&input)?);
        if let Some(receipt) = self.state.namespace.as_ref().and_then(|n| n.receipts.get(&input.request_id)) {
            return if receipt.owner == principal.id && receipt.fingerprint == fingerprint {
                Ok(receipt.result.clone())
            } else {
                Err(Error::Conflict)
            };
        }
        if current.tombstoned {
            return Err(Error::NotFound);
        }
        if current.revision != input.expected_revision || current.entry.head != input.expected_head || current.entry.checkout.is_some() {
            return Err(Error::Conflict);
        }
        let mut state = self.state.clone();
        let mut result = current;
        result.revision = result.revision.checked_add(1).ok_or(Error::Integrity)?;
        let operation = match input.action {
            NamespaceAction::Rename { logical_path } => {
                validate_logical_path(&logical_path)?;
                // Rename changes only the visible alias. Retained documents
                // keep their IDs, versions and stable materialization paths;
                // create/import still reserve all retained physical paths.
                if self.namespace_path_conflict_inner(&logical_path, Some(&input.document), false) {
                    return Err(Error::Conflict);
                }
                result.entry.logical_path = logical_path;
                state.documents.insert(input.document.clone(), result.entry.clone());
                "document.rename"
            }
            NamespaceAction::Tombstone => {
                if referenced || self.state.versions.iter().any(|v| v.version.dependencies.iter().any(|r| r.document == input.document)) {
                    return Err(Error::Referenced);
                }
                result.tombstoned = true;
                "document.tombstone"
            }
        };
        let namespace = state.namespace.get_or_insert_with(NamespaceState::default);
        namespace.materialization_paths.entry(input.document.clone()).or_insert_with(|| result.materialization_path.clone());
        namespace.last_document = input.document.clone();
        namespace.revisions.insert(input.document.clone(), result.revision);
        if result.tombstoned {
            namespace.deleted.insert(input.document);
        }
        if namespace.receipts.len() >= 256 {
            let key = namespace.receipts.keys().next().cloned().ok_or(Error::Integrity)?;
            namespace.receipts.remove(&key);
        }
        namespace.receipts.insert(input.request_id, NamespaceReceipt { owner: principal.id.clone(), fingerprint, result: result.clone() });
        self.publish_as(state, &principal.id, operation)?;
        Ok(result)
    }
}

impl NamespaceMetadata {
    /// Validate untrusted namespace output before any client uses its locator.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let entry = &self.entry;
        if !crate::valid_id(&entry.document)
            || entry.head.is_some_and(|head| head == 0 || head > MAX_VERSIONS as u64)
            || (self.revision == 0 && (self.tombstoned || self.materialization_path != entry.logical_path))
            || entry.head_author.as_ref().is_some_and(|author| !label(author))
            || entry.checkout.as_ref().is_some_and(|checkout| {
                !label(&checkout.owner) || !label(&checkout.workspace) || !label(&checkout.machine) || checkout.base_version != entry.head
            })
            || (self.tombstoned && entry.checkout.is_some())
            || [&entry.logical_path, &self.materialization_path]
                .iter()
                .any(|path| path.split('/').any(|part| part.eq_ignore_ascii_case(".solidcraft-pdm")))
        {
            return Err(Error::Invalid("namespace metadata"));
        }
        validate_logical_path(&entry.logical_path)?;
        validate_logical_path(&self.materialization_path)
    }
}
