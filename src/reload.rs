use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tracing::{error, info};

/// Reloader is a trait for objects that support live reloading.
pub trait Reloader: Send + Sync {
    fn reload(&self, reader: Box<dyn io::Read + Send>) -> io::Result<()>;
    fn period(&self) -> Duration;
}

/// Stoppable is a trait for Reloaders that can be stopped.
pub trait Stoppable {
    fn stop(&self);
    fn stopped(&self) -> bool;
}

/// Periodically reload a config file.
/// Returns when the reloader period is 0 (disabled) or negative (stopped).
pub async fn period_reload(reloader: &dyn Reloader, config_file: &str) -> io::Result<()> {
    if config_file.is_empty() {
        return Ok(());
    }

    let mut last_mod = SystemTime::UNIX_EPOCH;

    loop {
        let period = reloader.period();
        if period == Duration::ZERO {
            info!("[reload] disabled: {}", config_file);
            return Ok(());
        }

        let path = Path::new(config_file);
        let metadata = fs::metadata(path)?;
        let mod_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        if last_mod != SystemTime::UNIX_EPOCH && mod_time != last_mod {
            info!("[reload] {}", config_file);
            let f = fs::File::open(path)?;
            if let Err(e) = reloader.reload(Box::new(f)) {
                error!("[reload] {}: {}", config_file, e);
            }
        }

        last_mod = mod_time;

        let sleep_dur = if period < Duration::from_secs(1) {
            Duration::from_secs(1)
        } else {
            period
        };

        tokio::time::sleep(sleep_dur).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct MockReloader {
        count: Arc<AtomicU32>,
        period: Duration,
    }

    impl Reloader for MockReloader {
        fn reload(&self, _reader: Box<dyn io::Read + Send>) -> io::Result<()> {
            self.count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn period(&self) -> Duration {
            self.period
        }
    }

    #[test]
    fn test_reloader_trait() {
        let count = Arc::new(AtomicU32::new(0));
        let reloader = MockReloader {
            count: count.clone(),
            period: Duration::from_secs(1),
        };

        // Test reload
        let data: &[u8] = b"test data";
        reloader.reload(Box::new(data)).unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);

        reloader.reload(Box::new(&b"more"[..])).unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_zero_period_means_disabled() {
        let reloader = MockReloader {
            count: Arc::new(AtomicU32::new(0)),
            period: Duration::ZERO,
        };
        assert_eq!(reloader.period(), Duration::ZERO);
    }
}
