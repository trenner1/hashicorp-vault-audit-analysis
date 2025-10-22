use vault_audit_tools::utils::progress::ProgressBar;
use std::thread;
use std::time::Duration;

#[test]
fn test_progress_bar_new() {
    let pb = ProgressBar::new(100, "Test");
    // Just verify it doesn't panic
    drop(pb);
}

#[test]
fn test_progress_bar_new_spinner() {
    let pb = ProgressBar::new_spinner("Spinner Test");
    drop(pb);
}

#[test]
fn test_progress_bar_update() {
    let mut pb = ProgressBar::new(100, "Update Test");
    pb.update(50);
    pb.update(100);
    drop(pb);
}

#[test]
fn test_progress_bar_inc() {
    let mut pb = ProgressBar::new(10, "Inc Test");
    pb.inc();
    pb.inc();
    pb.inc();
    drop(pb);
}

#[test]
fn test_progress_bar_render() {
    let mut pb = ProgressBar::new(100, "Render Test");
    pb.render();
    pb.update(25);
    pb.render();
    pb.update(50);
    pb.render();
    pb.update(75);
    pb.render();
    pb.update(100);
    pb.render();
    drop(pb);
}

#[test]
fn test_progress_bar_finish() {
    let mut pb = ProgressBar::new(100, "Finish Test");
    pb.update(100);
    pb.finish();
}

#[test]
fn test_progress_bar_finish_with_message() {
    let mut pb = ProgressBar::new(100, "Custom Finish");
    pb.update(100);
    pb.finish_with_message("All done!");
}

#[test]
fn test_progress_bar_spinner_mode() {
    let mut pb = ProgressBar::new_spinner("Loading");
    pb.update(10);
    pb.update(20);
    pb.update(30);
    pb.finish();
}

#[test]
fn test_progress_bar_zero_total() {
    let mut pb = ProgressBar::new(0, "Zero Total");
    pb.update(0);
    pb.render();
    pb.finish();
}

#[test]
fn test_progress_bar_rapid_updates() {
    let mut pb = ProgressBar::new(1000, "Rapid");
    for i in 0..1000 {
        pb.update(i);
    }
    pb.finish();
}

#[test]
fn test_progress_bar_partial_progress() {
    let mut pb = ProgressBar::new(200, "Partial");
    pb.update(50);  // 25%
    pb.update(100); // 50%
    pb.update(150); // 75%
    pb.finish();
}

#[test]
fn test_progress_bar_over_100_percent() {
    let mut pb = ProgressBar::new(100, "Over 100");
    pb.update(150); // Over 100% - should cap at 100%
    pb.finish();
}

#[test]
fn test_progress_bar_multiple_renders() {
    let mut pb = ProgressBar::new(100, "Multiple Renders");
    for _ in 0..5 {
        pb.render();
    }
    pb.finish();
}

#[test]
fn test_progress_bar_slow_updates() {
    let mut pb = ProgressBar::new(5, "Slow");
    pb.update(1);
    thread::sleep(Duration::from_millis(250)); // Ensure enough time passes
    pb.update(2);
    thread::sleep(Duration::from_millis(250));
    pb.update(3);
    pb.finish();
}

#[test]
fn test_progress_bar_spinner_increments() {
    let mut pb = ProgressBar::new_spinner("Spinning");
    for i in 1..=10 {
        pb.update(i);
        pb.render(); // Force render to cycle spinner
    }
    pb.finish();
}

#[test]
fn test_progress_bar_large_numbers() {
    let mut pb = ProgressBar::new(1_000_000, "Large");
    pb.update(250_000);
    pb.update(500_000);
    pb.update(750_000);
    pb.update(1_000_000);
    pb.finish();
}

#[test]
fn test_progress_bar_finish_without_updates() {
    let mut pb = ProgressBar::new(100, "No Updates");
    pb.finish();
}

#[test]
fn test_progress_bar_spinner_finish_without_updates() {
    let mut pb = ProgressBar::new_spinner("Spinner No Updates");
    pb.finish();
}
