use std::time::{Duration, Instant};

use anyhow::{Result, bail};

const MINIMUM_BURST_BYTES: u64 = 16 * 1024;
const MAXIMUM_BURST_BYTES: u64 = 4 * 1024 * 1024;

pub struct SessionPolicy {
    deadline: Instant,
    quota: Option<u64>,
    transferred: u64,
    bucket: TokenBucket,
}

struct TokenBucket {
    rate: u64,
    capacity: u64,
    tokens: u64,
    updated_at: Instant,
}

impl SessionPolicy {
    pub fn new(
        lifetime_seconds: u32,
        bandwidth_bytes_per_second: u64,
        quota_bytes: u64,
        now: Instant,
    ) -> Result<Self> {
        if !(60..=86400).contains(&lifetime_seconds) {
            bail!("invalid session lifetime");
        }
        if !(1024..=1024 * 1024 * 1024).contains(&bandwidth_bytes_per_second) {
            bail!("invalid session bandwidth");
        }
        Ok(Self {
            deadline: now + Duration::from_secs(lifetime_seconds as u64),
            quota: (quota_bytes != 0).then_some(quota_bytes),
            transferred: 0,
            bucket: TokenBucket {
                rate: bandwidth_bytes_per_second,
                capacity: bandwidth_bytes_per_second
                    .clamp(MINIMUM_BURST_BYTES, MAXIMUM_BURST_BYTES),
                tokens: bandwidth_bytes_per_second.clamp(MINIMUM_BURST_BYTES, MAXIMUM_BURST_BYTES),
                updated_at: now,
            },
        })
    }

    pub fn reserve(&mut self, bytes: usize, now: Instant) -> Result<Duration> {
        if now >= self.deadline {
            bail!("session lifetime expired");
        }
        let bytes = u64::try_from(bytes)?;
        let next_total = self
            .transferred
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("session quota counter overflow"))?;
        if self.quota.is_some_and(|quota| next_total > quota) {
            bail!("session quota exceeded");
        }
        let delay = self.bucket.reserve(bytes, now);
        if now + delay >= self.deadline {
            bail!("session lifetime expires during shaping");
        }
        self.transferred = next_total;
        Ok(delay)
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl TokenBucket {
    fn reserve(&mut self, bytes: u64, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.updated_at);
        let replenished = elapsed
            .as_nanos()
            .saturating_mul(self.rate as u128)
            .checked_div(1_000_000_000)
            .unwrap_or(0)
            .min(u64::MAX as u128) as u64;
        self.tokens = self.tokens.saturating_add(replenished).min(self.capacity);
        self.updated_at = now;
        if bytes <= self.tokens {
            self.tokens -= bytes;
            return Duration::ZERO;
        }
        let deficit = bytes - self.tokens;
        self.tokens = 0;
        let nanos = (u128::from(deficit) * 1_000_000_000).div_ceil(u128::from(self.rate));
        let delay = Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64);
        self.updated_at = now + delay;
        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_quota() {
        let now = Instant::now();
        let mut policy = SessionPolicy::new(60, 1024, 1500, now).unwrap();
        assert_eq!(policy.reserve(1024, now).unwrap(), Duration::ZERO);
        assert!(policy.reserve(477, now + Duration::from_secs(1)).is_err());
    }

    #[test]
    fn replenishes_bandwidth_tokens() {
        let now = Instant::now();
        let mut policy = SessionPolicy::new(60, 1024, 0, now).unwrap();
        assert_eq!(policy.reserve(16 * 1024, now).unwrap(), Duration::ZERO);
        assert_eq!(
            policy.reserve(512, now).unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            policy
                .reserve(512, now + Duration::from_millis(500))
                .unwrap(),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn expires_session() {
        let now = Instant::now();
        let mut policy = SessionPolicy::new(60, 1024, 0, now).unwrap();
        assert!(policy.reserve(1, now + Duration::from_secs(60)).is_err());
    }
}
