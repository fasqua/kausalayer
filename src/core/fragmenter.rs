//! Amount Fragmentation for KausaLayer
//! Splits transfer amounts into random fragments to hide true amount

use rand::Rng;
use crate::error::{KausaError, Result};

/// Fragment represents a single piece of a fragmented transfer
#[derive(Debug, Clone)]
pub struct Fragment {
    /// Amount in lamports
    pub amount: u64,
    /// Delay in milliseconds before sending (for timing stagger)
    pub delay_ms: u64,
}

/// Fragmenter splits amounts into random pieces
pub struct Fragmenter {
    min_fragments: u8,
    max_fragments: u8,
    timing_window_ms: u64,
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self {
            min_fragments: 2,
            max_fragments: 6,
            timing_window_ms: 15000,
        }
    }
}

impl Fragmenter {
    pub fn new(min_fragments: u8, max_fragments: u8, timing_window_ms: u64) -> Self {
        Self {
            min_fragments: min_fragments.max(2),
            max_fragments: max_fragments.max(min_fragments),
            timing_window_ms,
        }
    }
    
    /// Fragment an amount into random pieces
    pub fn fragment(&self, total_lamports: u64) -> Result<Vec<Fragment>> {
        if total_lamports == 0 {
            return Err(KausaError::FragmentError("Amount cannot be zero".into()));
        }
        
        let mut rng = rand::thread_rng();
        
        // rand 0.7 syntax: gen_range(low, high) - exclusive high
        let num = rng.gen_range(self.min_fragments, self.max_fragments + 1) as usize;
        
        let min_per = 5000u64;
        let min_total = min_per * num as u64;
        
        if total_lamports < min_total {
            return Err(KausaError::FragmentError(
                format!("Amount too small for {} fragments", num)
            ));
        }
        
        let mut fragments = self.random_split(total_lamports, num, &mut rng)?;
        self.add_timing(&mut fragments, &mut rng);
        
        Ok(fragments)
    }
    
    pub fn fragment_instant(&self, total_lamports: u64) -> Result<Vec<Fragment>> {
        let mut fragments = self.fragment(total_lamports)?;
        for f in &mut fragments {
            f.delay_ms = 0;
        }
        Ok(fragments)
    }
    
    fn random_split<R: Rng>(&self, total: u64, n: usize, rng: &mut R) -> Result<Vec<Fragment>> {
        let min_each = 5000u64;
        let distributable = total - (min_each * n as u64);
        
        // Generate n-1 random split points (rand 0.7 syntax)
        let mut points: Vec<u64> = (0..n-1)
            .map(|_| rng.gen_range(0, distributable + 1))
            .collect();
        points.sort();
        
        let mut amounts = Vec::with_capacity(n);
        let mut prev = 0u64;
        
        for point in points {
            amounts.push(min_each + (point - prev));
            prev = point;
        }
        amounts.push(min_each + (distributable - prev));
        
        let mut fragments: Vec<Fragment> = amounts
            .into_iter()
            .map(|amount| Fragment { amount, delay_ms: 0 })
            .collect();
        
        // Shuffle (rand 0.7 syntax)
        for i in (1..fragments.len()).rev() {
            let j = rng.gen_range(0, i + 1);
            fragments.swap(i, j);
        }
        
        Ok(fragments)
    }
    
    fn add_timing<R: Rng>(&self, fragments: &mut [Fragment], rng: &mut R) {
        if fragments.is_empty() || self.timing_window_ms == 0 {
            return;
        }
        
        for (i, frag) in fragments.iter_mut().enumerate() {
            frag.delay_ms = if i == 0 { 
                0 
            } else { 
                rng.gen_range(0, self.timing_window_ms)
            };
        }
        
        fragments.sort_by_key(|f| f.delay_ms);
    }
    
    pub fn get_range(&self) -> (u8, u8) {
        (self.min_fragments, self.max_fragments)
    }
}

pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

pub fn sol_to_lamports(sol: f64) -> u64 {
    (sol * 1_000_000_000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_sum_preserved() {
        let frag = Fragmenter::default();
        let amount = 1_000_000_000u64;
        
        for _ in 0..10 {
            let result = frag.fragment(amount).unwrap();
            let total: u64 = result.iter().map(|f| f.amount).sum();
            assert_eq!(total, amount);
        }
    }

    #[test]
    fn test_fragment_count_in_range() {
        let frag = Fragmenter::new(3, 5, 10000);
        
        for _ in 0..10 {
            let result = frag.fragment(1_000_000_000).unwrap();
            assert!(result.len() >= 3);
            assert!(result.len() <= 5);
        }
    }

    #[test]
    fn test_minimum_amount() {
        let frag = Fragmenter::new(2, 2, 0);
        
        let result = frag.fragment(10_000);
        assert!(result.is_ok());
        
        let result = frag.fragment(8_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_instant_no_delays() {
        let frag = Fragmenter::default();
        let result = frag.fragment_instant(1_000_000_000).unwrap();
        
        for f in &result {
            assert_eq!(f.delay_ms, 0);
        }
    }

    #[test]
    fn test_sol_conversion() {
        assert_eq!(sol_to_lamports(1.0), 1_000_000_000);
        assert_eq!(lamports_to_sol(1_000_000_000), 1.0);
    }
}
