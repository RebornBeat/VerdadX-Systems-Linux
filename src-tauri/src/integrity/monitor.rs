use notify::{RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

pub struct IntegrityMonitor {
    baseline: Arc<RwLock<SystemBaseline>>,
    verifier: Arc<RwLock<IntegrityVerifier>>,
    scanner: Arc<RwLock<FileScanner>>,
    watcher: Arc<RwLock<FileWatcher>>,
    state: Arc<RwLock<MonitorState>>,
    config: Arc<RwLock<MonitorConfig>>,
    event_sender: mpsc::Sender<IntegrityEvent>,
}

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub monitored_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
    pub scan_interval: Duration,
    pub hash_algorithm: HashAlgorithm,
    pub verification_policy: VerificationPolicy,
    pub alert_policy: AlertPolicy,
}

#[derive(Debug)]
pub enum IntegrityError {
    BaselineError(String),
    VerificationError(String),
    ScanError(String),
    WatchError(String),
    IOError(std::io::Error),
    HashError(String),
}

impl IntegrityMonitor {
    pub async fn new(config: MonitorConfig) -> Result<Self, IntegrityError> {
        let (tx, rx) = mpsc::channel(1000);

        let monitor = Self {
            baseline: Arc::new(RwLock::new(SystemBaseline::new(&config)?)),
            verifier: Arc::new(RwLock::new(IntegrityVerifier::new(&config)?)),
            scanner: Arc::new(RwLock::new(FileScanner::new(&config)?)),
            watcher: Arc::new(RwLock::new(FileWatcher::new(&config)?)),
            state: Arc::new(RwLock::new(MonitorState::new())),
            config: Arc::new(RwLock::new(config)),
            event_sender: tx,
        };

        // Start the event processing loop
        monitor.start_event_processor(rx).await?;

        Ok(monitor)
    }

    pub async fn start_monitoring(&self) -> Result<(), IntegrityError> {
        // Initialize baseline if not exists
        self.initialize_baseline().await?;

        // Start file system watcher
        self.start_watcher().await?;

        // Start periodic scanning
        self.start_periodic_scan().await?;

        Ok(())
    }

    async fn initialize_baseline(&self) -> Result<(), IntegrityError> {
        let mut baseline = self.baseline.write().await;

        if !baseline.exists() {
            let scanner = self.scanner.read().await;
            let scan_result = scanner.perform_full_scan().await?;
            baseline.create_from_scan(scan_result).await?;
        }

        Ok(())
    }

    async fn start_watcher(&self) -> Result<(), IntegrityError> {
        let mut watcher = self.watcher.write().await;
        let event_sender = self.event_sender.clone();

        watcher.start(move |event| {
            let _ = event_sender.try_send(IntegrityEvent::FileSystem(event));
        })?;

        Ok(())
    }

    async fn handle_integrity_event(&self, event: IntegrityEvent) -> Result<(), IntegrityError> {
        match event {
            IntegrityEvent::FileSystem(fs_event) => self.handle_fs_event(fs_event).await?,
            IntegrityEvent::Verification(verify_event) => {
                self.handle_verification_event(verify_event).await?
            }
            IntegrityEvent::Scan(scan_event) => self.handle_scan_event(scan_event).await?,
        }

        Ok(())
    }

    async fn verify_file_integrity(
        &self,
        path: &Path,
    ) -> Result<VerificationResult, IntegrityError> {
        let baseline = self.baseline.read().await;
        let verifier = self.verifier.read().await;

        // Get baseline entry
        let baseline_entry = baseline.get_entry(path)?;

        // Verify current state against baseline
        verifier.verify_file(path, baseline_entry).await
    }
}
