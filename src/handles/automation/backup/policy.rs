use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::str::FromStr;

/// Retention policy for backup pruning operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetentionPolicy {
    pub keep_last: Option<u32>,
    pub keep_daily: Option<u32>,
    pub keep_weekly: Option<u32>,
    pub keep_monthly: Option<u32>,
    pub keep_yearly: Option<u32>,
}

impl RetentionPolicy {
    /// Create a new empty retention policy
    pub fn new() -> Self {
        Self {
            keep_last: None,
            keep_daily: None,
            keep_weekly: None,
            keep_monthly: None,
            keep_yearly: None,
        }
    }

    /// Check if the policy is empty (no retention rules specified)
    pub fn is_empty(&self) -> bool {
        self.keep_last.is_none() 
            && self.keep_daily.is_none() 
            && self.keep_weekly.is_none() 
            && self.keep_monthly.is_none() 
            && self.keep_yearly.is_none()
    }

    /// Parse a retention policy from a string
    /// Format: "keep-last:N,keep-daily:N,keep-weekly:N,keep-monthly:N,keep-yearly:N"
    /// Example: "keep-last:10,keep-daily:7,keep-weekly:4,keep-monthly:12"
    pub fn from_string(policy_str: &str) -> Result<Self> {
        if policy_str.trim().is_empty() {
            return Err(anyhow!("retention policy cannot be empty"));
        }

        let mut policy = RetentionPolicy::new();
        let parts: Vec<&str> = policy_str.split(',').collect();

        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let key_value: Vec<&str> = part.split(':').collect();
            if key_value.len() != 2 {
                return Err(anyhow!("invalid policy format '{}', expected 'key:value'", part));
            }

            let key = key_value[0].trim();
            let value_str = key_value[1].trim();
            
            let value: u32 = value_str.parse()
                .map_err(|_| anyhow!("invalid number '{}' for key '{}'", value_str, key))?;
            
            if value == 0 {
                return Err(anyhow!("retention value cannot be zero for key '{}'", key));
            }

            match key {
                "keep-last" => policy.keep_last = Some(value),
                "keep-daily" => policy.keep_daily = Some(value),
                "keep-weekly" => policy.keep_weekly = Some(value),
                "keep-monthly" => policy.keep_monthly = Some(value),
                "keep-yearly" => policy.keep_yearly = Some(value),
                _ => return Err(anyhow!("unknown retention key '{}'. Supported: keep-last, keep-daily, keep-weekly, keep-monthly, keep-yearly", key)),
            }
        }

        if policy.is_empty() {
            return Err(anyhow!("retention policy cannot be empty after parsing"));
        }

        Ok(policy)
    }

    /// Convert the policy to restic command arguments
    pub fn to_restic_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        
        if let Some(n) = self.keep_last {
            args.push(format!("--keep-last={}", n));
        }
        if let Some(n) = self.keep_daily {
            args.push(format!("--keep-daily={}", n));
        }
        if let Some(n) = self.keep_weekly {
            args.push(format!("--keep-weekly={}", n));
        }
        if let Some(n) = self.keep_monthly {
            args.push(format!("--keep-monthly={}", n));
        }
        if let Some(n) = self.keep_yearly {
            args.push(format!("--keep-yearly={}", n));
        }
        
        args
    }

    /// Convert the policy to borg command arguments
    pub fn to_borg_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        
        if let Some(n) = self.keep_last {
            args.push(format!("--keep-last={}", n));
        }
        if let Some(n) = self.keep_daily {
            args.push(format!("--keep-daily={}", n));
        }
        if let Some(n) = self.keep_weekly {
            args.push(format!("--keep-weekly={}", n));
        }
        if let Some(n) = self.keep_monthly {
            args.push(format!("--keep-monthly={}", n));
        }
        if let Some(n) = self.keep_yearly {
            args.push(format!("--keep-yearly={}", n));
        }
        
        args
    }

    /// Serialize the policy to a JSON-friendly format for output
    pub fn to_json_map(&self) -> HashMap<String, u32> {
        let mut map = HashMap::new();
        
        if let Some(n) = self.keep_last {
            map.insert("keep_last".to_string(), n);
        }
        if let Some(n) = self.keep_daily {
            map.insert("keep_daily".to_string(), n);
        }
        if let Some(n) = self.keep_weekly {
            map.insert("keep_weekly".to_string(), n);
        }
        if let Some(n) = self.keep_monthly {
            map.insert("keep_monthly".to_string(), n);
        }
        if let Some(n) = self.keep_yearly {
            map.insert("keep_yearly".to_string(), n);
        }
        
        map
    }
}

impl FromStr for RetentionPolicy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        RetentionPolicy::from_string(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_policy() {
        let policy = RetentionPolicy::from_string("keep-last:10,keep-daily:7").unwrap();
        assert_eq!(policy.keep_last, Some(10));
        assert_eq!(policy.keep_daily, Some(7));
        assert_eq!(policy.keep_weekly, None);
    }

    #[test]
    fn test_parse_full_policy() {
        let policy = RetentionPolicy::from_string(
            "keep-last:10,keep-daily:7,keep-weekly:4,keep-monthly:12,keep-yearly:2"
        ).unwrap();
        assert_eq!(policy.keep_last, Some(10));
        assert_eq!(policy.keep_daily, Some(7));
        assert_eq!(policy.keep_weekly, Some(4));
        assert_eq!(policy.keep_monthly, Some(12));
        assert_eq!(policy.keep_yearly, Some(2));
    }

    #[test]
    fn test_parse_empty_policy() {
        assert!(RetentionPolicy::from_string("").is_err());
        assert!(RetentionPolicy::from_string("   ").is_err());
    }

    #[test]
    fn test_parse_invalid_format() {
        assert!(RetentionPolicy::from_string("keep-last=10").is_err());
        assert!(RetentionPolicy::from_string("keep-last:10:extra").is_err());
        assert!(RetentionPolicy::from_string("invalid").is_err());
    }

    #[test]
    fn test_parse_invalid_numbers() {
        assert!(RetentionPolicy::from_string("keep-last:abc").is_err());
        assert!(RetentionPolicy::from_string("keep-last:-5").is_err());
        assert!(RetentionPolicy::from_string("keep-last:0").is_err());
    }

    #[test]
    fn test_parse_unknown_keys() {
        assert!(RetentionPolicy::from_string("keep-unknown:5").is_err());
        assert!(RetentionPolicy::from_string("keep-last:10,keep-invalid:5").is_err());
    }

    #[test]
    fn test_restic_args() {
        let policy = RetentionPolicy::from_string("keep-last:10,keep-daily:7").unwrap();
        let args = policy.to_restic_args();
        assert!(args.contains(&"--keep-last=10".to_string()));
        assert!(args.contains(&"--keep-daily=7".to_string()));
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn test_borg_args() {
        let policy = RetentionPolicy::from_string("keep-weekly:4,keep-monthly:12").unwrap();
        let args = policy.to_borg_args();
        assert!(args.contains(&"--keep-weekly=4".to_string()));
        assert!(args.contains(&"--keep-monthly=12".to_string()));
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn test_json_map() {
        let policy = RetentionPolicy::from_string("keep-last:10,keep-daily:7").unwrap();
        let map = policy.to_json_map();
        assert_eq!(map.get("keep_last"), Some(&10));
        assert_eq!(map.get("keep_daily"), Some(&7));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_is_empty() {
        let empty = RetentionPolicy::new();
        assert!(empty.is_empty());

        let not_empty = RetentionPolicy::from_string("keep-last:1").unwrap();
        assert!(!not_empty.is_empty());
    }
}