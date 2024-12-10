use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub source: String,
    pub category: LogCategory,
    pub message: String,
    pub metadata: LogMetadata,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogCategory {
    Security,
    System,
    Application,
    Audit,
    Performance,
    Network,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMetadata {
    pub process_id: u32,
    pub thread_id: u64,
    pub user: Option<String>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub stack_trace: Option<Vec<String>>,
}

pub struct Logger {
    config: Arc<RwLock<LogConfig>>,
    aggregator: Arc<LogAggregator>,
    analyzer: Arc<LogAnalyzer>,
    storage: Arc<LogStorage>,
    rotator: Arc<LogRotator>,
    event_sender: mpsc::Sender<LogEntry>,
    alert_channel: broadcast::Sender<LogAlert>,
}

#[derive(Debug)]
pub enum LogError {
    StorageError(String),
    AnalysisError(String),
    AggregationError(String),
    RotationError(String),
    ConfigError(String),
}

impl Logger {
    pub async fn new(config: LogConfig) -> Result<Self, LogError> {
        let (event_tx, event_rx) = mpsc::channel(10000);
        let (alert_tx, _) = broadcast::channel(1000);

        let storage = Arc::new(LogStorage::new(&config.storage).await?);
        let aggregator = Arc::new(LogAggregator::new(&config.aggregation).await?);
        let analyzer = Arc::new(LogAnalyzer::new(&config.analysis).await?);
        let rotator = Arc::new(LogRotator::new(&config.rotation).await?);

        let logger = Self {
            config: Arc::new(RwLock::new(config)),
            aggregator,
            analyzer,
            storage,
            rotator,
            event_sender: event_tx,
            alert_channel: alert_tx,
        };

        // Start log processing pipeline
        logger.start_processing_pipeline(event_rx).await?;

        Ok(logger)
    }

    pub async fn log(&self, entry: LogEntry) -> Result<(), LogError> {
        // Validate log entry
        self.validate_entry(&entry)?;

        // Send to processing pipeline
        self.event_sender
            .send(entry)
            .await
            .map_err(|e| LogError::StorageError(e.to_string()))?;

        Ok(())
    }

    async fn start_processing_pipeline(
        &self,
        mut event_rx: mpsc::Receiver<LogEntry>,
    ) -> Result<(), LogError> {
        let aggregator = Arc::clone(&self.aggregator);
        let analyzer = Arc::clone(&self.analyzer);
        let storage = Arc::clone(&self.storage);
        let rotator = Arc::clone(&self.rotator);
        let alert_tx = self.alert_channel.clone();

        tokio::spawn(async move {
            while let Some(entry) = event_rx.recv().await {
                // Process through pipeline
                if let Err(e) = Self::process_log_entry(
                    &entry,
                    &aggregator,
                    &analyzer,
                    &storage,
                    &rotator,
                    &alert_tx,
                )
                .await
                {
                    eprintln!("Error processing log entry: {:?}", e);
                }
            }
        });

        Ok(())
    }

    async fn process_log_entry(
        entry: &LogEntry,
        aggregator: &LogAggregator,
        analyzer: &LogAnalyzer,
        storage: &LogStorage,
        rotator: &LogRotator,
        alert_tx: &broadcast::Sender<LogAlert>,
    ) -> Result<(), LogError> {
        // Aggregate related logs
        let aggregated = aggregator.process_entry(entry).await?;

        // Analyze for patterns and anomalies
        let analysis = analyzer.analyze(&aggregated).await?;

        // Check if rotation is needed
        if rotator.should_rotate().await? {
            rotator.rotate_logs(storage).await?;
        }

        // Store the log entry
        storage.store(entry).await?;

        // Send alerts if necessary
        if analysis.should_alert() {
            let alert = LogAlert::from_analysis(analysis);
            let _ = alert_tx.send(alert);
        }

        Ok(())
    }
}
