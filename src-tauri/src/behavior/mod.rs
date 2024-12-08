mod analyzer;
mod engine;
mod events;
mod patterns;

pub use analyzer::ThreatAnalyzer;
pub use engine::BehaviorEngine;
pub use events::{EventContext, EventType, SystemEvent};
pub use patterns::{BehaviorPattern, PatternMatcher};
