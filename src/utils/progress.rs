//! Progress bar utilities using indicatif
//!
//! Provides a wrapper around indicatif's `ProgressBar` for consistent
//! progress reporting across all commands.

use indicatif::{ProgressBar as IndicatifBar, ProgressStyle};

/// Progress bar wrapper for displaying processing status
pub struct ProgressBar {
    bar: IndicatifBar,
}

impl ProgressBar {
    /// Create a new progress bar with known total
    pub fn new(total: usize, label: &str) -> Self {
        let bar = IndicatifBar::new(total as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{msg} [{bar:40.cyan/blue}] {percent:>3}% ({pos}/{len}) ({per_sec}) {eta}",
                )
                .expect("Invalid progress bar template")
                .progress_chars("█░"),
        );
        bar.set_message(label.to_string());

        Self { bar }
    }

    /// Create a new progress bar with unknown total (spinner mode)
    #[allow(dead_code)]
    pub fn new_spinner(label: &str) -> Self {
        let bar = IndicatifBar::new_spinner();
        bar.set_style(
            ProgressStyle::default_spinner()
                .template("{msg} {spinner} {pos}")
                .expect("Invalid spinner template"),
        );
        bar.set_message(label.to_string());

        Self { bar }
    }

    /// Update progress
    pub fn update(&self, current: usize) {
        self.bar.set_position(current as u64);
    }

    /// Increment progress by 1
    #[allow(dead_code)]
    pub fn inc(&self) {
        self.bar.inc(1);
    }

    /// Force render (indicatif handles this automatically)
    #[allow(dead_code)]
    pub fn render(&self) {
        // indicatif handles rendering automatically
        self.bar.tick();
    }

    /// Finish the progress bar
    pub fn finish(&self) {
        self.bar.finish();
    }

    /// Finish with custom message
    pub fn finish_with_message(&self, message: &str) {
        self.bar.finish_with_message(message.to_string());
    }

    /// Print a message above the progress bar without disturbing it
    pub fn println<S: AsRef<str>>(&self, msg: S) {
        self.bar.println(msg.as_ref());
    }
}
