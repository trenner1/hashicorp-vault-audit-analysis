use crate::utils::format::format_number;
use std::io::{self, Write};
use std::time::{Duration, Instant};

/// Progress bar for displaying processing status
pub struct ProgressBar {
    total: Option<usize>,
    current: usize,
    last_update: Instant,
    update_interval: Duration,
    label: String,
    started: Instant,
    render_count: usize,
}

impl ProgressBar {
    /// Create a new progress bar with known total
    pub fn new(total: usize, label: &str) -> Self {
        let mut pb = Self {
            total: Some(total),
            current: 0,
            last_update: Instant::now(),
            update_interval: Duration::from_millis(200), // Update every 200ms
            label: label.to_string(),
            started: Instant::now(),
            render_count: 0,
        };
        pb.render(); // Show initial state
        pb
    }

    /// Create a new progress bar with unknown total (spinner mode)
    pub fn new_spinner(label: &str) -> Self {
        let mut pb = Self {
            total: None,
            current: 0,
            last_update: Instant::now(),
            update_interval: Duration::from_millis(200),
            label: label.to_string(),
            started: Instant::now(),
            render_count: 0,
        };
        pb.render(); // Show initial state
        pb
    }

    /// Update progress (only renders if enough time has passed)
    pub fn update(&mut self, current: usize) {
        self.current = current;

        if self.last_update.elapsed() >= self.update_interval {
            self.render();
            self.last_update = Instant::now();
        }
    }

    /// Increment progress by 1
    #[allow(dead_code)]
    pub fn inc(&mut self) {
        self.update(self.current + 1);
    }

    /// Force render regardless of update interval
    pub fn render(&mut self) {
        self.render_count += 1;

        if let Some(total) = self.total {
            let percentage = if total > 0 {
                (self.current as f64 / total as f64 * 100.0).min(100.0)
            } else {
                0.0
            };

            let bar_width = 40;
            let filled = (bar_width as f64 * percentage / 100.0) as usize;
            let empty = bar_width - filled;

            let bar = format!("[{}{}]", "█".repeat(filled), "░".repeat(empty));

            // Calculate ETA
            let elapsed = self.started.elapsed();
            let eta_info = if self.current > 0 && percentage > 0.1 {
                let estimated_total_time = elapsed.as_secs_f64() / (percentage / 100.0);
                let remaining_time = estimated_total_time - elapsed.as_secs_f64();

                if remaining_time > 0.0 {
                    let remaining_mins = (remaining_time / 60.0) as u64;
                    let remaining_secs = (remaining_time % 60.0) as u64;
                    format!(" ETA: {}:{:02}", remaining_mins, remaining_secs)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            // Calculate speed
            let speed_info = if elapsed.as_secs() > 0 {
                let rate = self.current as f64 / elapsed.as_secs_f64();
                format!(" ({}/s)", format_number(rate as usize))
            } else {
                String::new()
            };

            eprint!(
                "\r{} {} {:>6.1}% ({}/{}){}{}",
                self.label,
                bar,
                percentage,
                format_number(self.current),
                format_number(total),
                speed_info,
                eta_info
            );
        } else {
            // Spinner mode for unknown total
            let spinner = ['|', '/', '-', '\\'];
            let idx = self.render_count % spinner.len();

            eprint!(
                "\r{} {} {}",
                self.label,
                spinner[idx],
                format_number(self.current)
            );
        }

        let _ = io::stderr().flush();
    }

    /// Finish the progress bar and print final message
    pub fn finish(&mut self) {
        self.render();
        let elapsed = self.started.elapsed();
        let rate = if elapsed.as_secs() > 0 {
            format!(
                "{}/s",
                format_number(self.current / elapsed.as_secs() as usize)
            )
        } else {
            String::new()
        };

        eprintln!(
            " Done in {:.1}s {}",
            elapsed.as_secs_f64(),
            if rate.is_empty() {
                String::new()
            } else {
                format!("({})", rate)
            }
        );
    }

    /// Finish with custom message
    pub fn finish_with_message(&mut self, message: &str) {
        self.render();
        eprintln!(" {}", message);
    }
}
