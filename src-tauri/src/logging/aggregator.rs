pub struct LogAggregator {
    config: AggregationConfig,
    patterns: Vec<AggregationPattern>,
    state: Arc<RwLock<AggregationState>>,
}

#[derive(Debug, Clone)]
pub struct AggregationPattern {
    pub name: String,
    pub conditions: Vec<AggregationCondition>,
    pub window: Duration,
    pub min_occurrences: usize,
}

impl LogAggregator {
    pub async fn process_entry(&self, entry: &LogEntry) -> Result<AggregatedLogs, LogError> {
        let mut state = self.state.write().await;
        let mut aggregated = Vec::new();

        // Check against active patterns
        for pattern in &self.patterns {
            if pattern.matches(entry) {
                let related = state.find_related_entries(entry, pattern).await?;
                if related.len() >= pattern.min_occurrences {
                    aggregated.push(AggregatedGroup {
                        pattern: pattern.clone(),
                        entries: related,
                    });
                }
            }
        }

        // Update state with new entry
        state.add_entry(entry.clone()).await?;

        Ok(AggregatedLogs { groups: aggregated })
    }
}
