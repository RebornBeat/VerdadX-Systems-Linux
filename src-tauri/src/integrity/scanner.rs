pub struct FileScanner {
    config: ScannerConfig,
    stats: Arc<RwLock<ScanStats>>,
}

impl FileScanner {
    pub async fn perform_full_scan(&self) -> Result<ScanResult, IntegrityError> {
        let mut results = Vec::new();

        for path in &self.config.monitored_paths {
            if self.should_scan(path) {
                let entries = self.scan_directory(path).await?;
                results.extend(entries);
            }
        }

        Ok(ScanResult {
            entries: results,
            timestamp: SystemTime::now(),
            stats: self.stats.read().await.clone(),
        })
    }

    async fn scan_directory(&self, path: &Path) -> Result<Vec<BaselineEntry>, IntegrityError> {
        let mut entries = Vec::new();
        let mut dirs_to_scan = vec![path.to_path_buf()];

        while let Some(dir) = dirs_to_scan.pop() {
            let read_dir = tokio::fs::read_dir(&dir).await?;

            tokio::pin!(read_dir);

            while let Some(entry) = read_dir.next_entry().await? {
                let path = entry.path();

                if self.should_exclude(&path) {
                    continue;
                }

                if path.is_dir() {
                    dirs_to_scan.push(path);
                } else {
                    entries.push(self.create_baseline_entry(&path).await?);
                }
            }
        }

        Ok(entries)
    }
}
