pub struct LogRotator {
    config: RotationConfig,
    state: Arc<RwLock<RotationState>>,
}

impl LogRotator {
    pub async fn should_rotate(&self) -> Result<bool, LogError> {
        let config = &self.config;
        let state = self.state.read().await;

        // Check size-based rotation
        if let Some(max_size) = config.max_size {
            if state.current_size >= max_size {
                return Ok(true);
            }
        }

        // Check time-based rotation
        if let Some(interval) = config.rotation_interval {
            if state.last_rotation.elapsed()? >= interval {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub async fn rotate_logs(&self, storage: &LogStorage) -> Result<(), LogError> {
        let mut state = self.state.write().await;

        // Create new log file
        let new_log_path = self.generate_new_log_path()?;

        // Archive current log
        self.archive_current_log(&state.current_log_path).await?;

        // Update state
        state.current_log_path = new_log_path;
        state.current_size = 0;
        state.last_rotation = SystemTime::now();

        // Clean up old logs if needed
        self.cleanup_old_logs().await?;

        Ok(())
    }
}
