pub struct LogStorage {
    config: StorageConfig,
    backend: Box<dyn StorageBackend>,
    encryption: Option<Box<dyn EncryptionProvider>>,
    index: Arc<RwLock<LogIndex>>,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn store(&self, entry: &LogEntry) -> Result<(), LogError>;
    async fn retrieve(&self, query: &LogQuery) -> Result<Vec<LogEntry>, LogError>;
    async fn delete(&self, query: &LogQuery) -> Result<(), LogError>;
}

impl LogStorage {
    pub async fn store(&self, entry: &LogEntry) -> Result<(), LogError> {
        // Encrypt if configured
        let encrypted_entry = if let Some(ref encryption) = self.encryption {
            encryption.encrypt(entry).await?
        } else {
            entry.clone()
        };

        // Store entry
        self.backend.store(&encrypted_entry).await?;

        // Update index
        self.index.write().await.add_entry(&encrypted_entry).await?;

        Ok(())
    }
}
