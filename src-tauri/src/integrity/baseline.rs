pub struct SystemBaseline {
    entries: HashMap<PathBuf, BaselineEntry>,
    metadata: BaselineMetadata,
    hash_cache: Arc<RwLock<HashMap<PathBuf, FileHash>>>,
}

#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub path: PathBuf,
    pub hash: FileHash,
    pub metadata: FileMetadata,
    pub permissions: FilePermissions,
    pub extended_attributes: Option<ExtendedAttributes>,
    pub signature: Option<FileSignature>,
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size: u64,
    pub created: SystemTime,
    pub modified: SystemTime,
    pub accessed: SystemTime,
    pub owner: String,
    pub group: String,
}

impl SystemBaseline {
    pub async fn create_from_scan(
        &mut self,
        scan_result: ScanResult,
    ) -> Result<(), IntegrityError> {
        for entry in scan_result.entries {
            self.add_entry(entry).await?;
        }

        // Update metadata
        self.metadata.last_updated = SystemTime::now();
        self.metadata.version += 1;

        // Save baseline
        self.save().await?;

        Ok(())
    }

    pub async fn verify_integrity(&self) -> Result<VerificationResult, IntegrityError> {
        let mut results = Vec::new();

        for (path, entry) in &self.entries {
            let current_hash = calculate_file_hash(path).await?;

            if current_hash != entry.hash {
                results.push(IntegrityViolation {
                    path: path.clone(),
                    violation_type: ViolationType::HashMismatch,
                    expected: entry.hash.clone(),
                    found: current_hash,
                });
            }

            // Verify metadata
            if let Err(e) = self.verify_metadata(path, &entry.metadata).await {
                results.push(IntegrityViolation {
                    path: path.clone(),
                    violation_type: ViolationType::MetadataChanged,
                    details: e.to_string(),
                });
            }

            // Verify permissions
            if let Err(e) = self.verify_permissions(path, &entry.permissions).await {
                results.push(IntegrityViolation {
                    path: path.clone(),
                    violation_type: ViolationType::PermissionChanged,
                    details: e.to_string(),
                });
            }
        }

        Ok(VerificationResult {
            violations: results,
        })
    }
}
