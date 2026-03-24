use anyhow::Result;
use std::fs;
use std::path::Path;

pub struct IgnorePatterns {
    patterns: Vec<String>,
}

impl IgnorePatterns {
    pub fn load(root_path: &Path) -> Result<Self> {
        let ignore_file = root_path.join(".guardianignore");
        
        if !ignore_file.exists() {
            return Ok(Self {
                patterns: Vec::new(),
            });
        }

        let content = fs::read_to_string(&ignore_file)?;
        let patterns: Vec<String> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_string())
            .collect();

        Ok(Self { patterns })
    }

    pub fn should_ignore(&self, path: &str) -> bool {
        for pattern in &self.patterns {
            if path.contains(pattern) {
                return true;
            }
            
            // Simple glob matching for * wildcard
            if pattern.contains('*') {
                let parts: Vec<&str> = pattern.split('*').collect();
                if parts.len() == 2 {
                    if path.starts_with(parts[0]) && path.ends_with(parts[1]) {
                        return true;
                    }
                }
            }
        }
        false
    }
}
