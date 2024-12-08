use std::collections::VecDeque;
use std::time::Duration;

struct PatternMatcher {
    pattern: Vec<SyscallPattern>,
    window: VecDeque<Syscall>,
    window_duration: Duration,
}

enum SyscallPattern {
    Sequence(Vec<u32>),               // Sequence of syscall numbers
    Frequency(u32, usize),            // (syscall_number, max_count)
    TimeWindow(u32, Duration, usize), // (syscall_number, duration, max_count)
    Custom(Box<dyn Fn(&[Syscall]) -> bool + Send + Sync>),
}

impl PatternMatcher {
    async fn check_pattern(&mut self, syscall: &Syscall) -> Result<bool, SyscallError> {
        // Add syscall to window
        self.window.push_back(syscall.clone());

        // Remove old syscalls
        self.cleanup_window();

        // Check patterns
        for pattern in &self.pattern {
            if self.matches_pattern(pattern)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn cleanup_window(&mut self) {
        let now = std::time::SystemTime::now();
        while let Some(syscall) = self.window.front() {
            if now
                .duration_since(syscall.timestamp)
                .unwrap_or(Duration::from_secs(0))
                > self.window_duration
            {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }

    fn matches_pattern(&self, pattern: &SyscallPattern) -> Result<bool, SyscallError> {
        match pattern {
            SyscallPattern::Sequence(seq) => self.check_sequence(seq),
            SyscallPattern::Frequency(syscall, max) => self.check_frequency(*syscall, *max),
            SyscallPattern::TimeWindow(syscall, duration, max) => {
                self.check_time_window(*syscall, *duration, *max)
            }
            SyscallPattern::Custom(checker) => Ok(checker(&self.window.make_contiguous())),
        }
    }
}
