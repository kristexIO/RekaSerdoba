use std::time::{Duration, Instant};

use anyhow::{Result, bail};

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
                capacity: bandwidth_bytes_per_second,
                tokens: bandwidth_bytes_per_second,
                updated_at: now,
            },
        })
    }

    pub fn charge(&mut self, bytes: usize, now: Instant) -> Result<()> {
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
        self.bucket.consume(bytes, now)?;
        self.transferred = next_total;
        Ok(())
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl TokenBucket {
    fn consume(&mut self, bytes: u64, now: Instant) -> Result<()> {
        let elapsed = now.saturating_duration_since(self.updated_at);
        let replenished = elapsed
            .as_nanos()
            .saturating_mul(self.rate as u128)
            .checked_div(1_000_000_000)
            .unwrap_or(0)
            .min(u64::MAX as u128) as u64;
        self.tokens = self.tokens.saturating_add(replenished).min(self.capacity);
        self.updated_at = now;
        if bytes > self.tokens {
            bail!("session bandwidth exceeded");
        }
        self.tokens -= bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_quota() {
        let now = Instant::now();
        let mut policy = SessionPolicy::new(60, 1024, 1500, now).unwrap();
        policy.charge(1024, now).unwrap();
        assert!(policy.charge(477, now + Duration::from_secs(1)).is_err());
    }

    #[test]
    fn replenishes_bandwidth_tokens() {
        let now = Instant::now();
        let mut policy = SessionPolicy::new(60, 1024, 0, now).unwrap();
        policy.charge(1024, now).unwrap();
        assert!(policy.charge(1, now).is_err());
        policy
            .charge(512, now + Duration::from_millis(500))
            .unwrap();
    }

    #[test]
    fn expires_session() {
        let now = Instant::now();
        let mut policy = SessionPolicy::new(60, 1024, 0, now).unwrap();
        assert!(policy.charge(1, now + Duration::from_secs(60)).is_err());
    }
}
