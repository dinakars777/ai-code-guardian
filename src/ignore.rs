use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::fs;
use std::path::Path;

pub struct IgnorePatterns {
    glob_set: GlobSet,
}

impl IgnorePatterns {
    pub fn load(root_path: &Path) -> Result<Self> {
        let ignore_file = root_path.join(".guardianignore");
        
        if !ignore_file.exists() {
            return Ok(Self {
                glob_set: GlobSet::empty(),
            });
        }

        let content = fs::read_to_string(&ignore_file)?;
        let mut builder = GlobSetBuilder::new();
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Add the glob pattern
            if let Ok(glob) = Glob::new(line) {
                builder.add(glob);
            }
        }

        let glob_set = builder.build()?;
        Ok(Self { glob_set })
    }

    pub fn should_ignore(&self, path: &str) -> bool {
        self.glob_set.is_match(path)
    }
}
