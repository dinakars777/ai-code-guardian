use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::patterns::PATTERNS;
use crate::report::{Issue, Report, Severity};
use crate::custom_rules::{load_custom_rules, CompiledRule};

pub struct Scanner {
    root_path: String,
    custom_rules: Vec<CompiledRule>,
}

impl Scanner {
    pub fn new(path: &str) -> Result<Self> {
        let root_path = fs::canonicalize(path)
            .context("Failed to resolve path")?
            .to_string_lossy()
            .to_string();

        let custom_rules = load_custom_rules(Path::new(&root_path))?;

        Ok(Self { root_path, custom_rules })
    }

    pub fn scan(&self, verbose: bool) -> Result<Report> {
        let mut issues = Vec::new();
        let mut files_scanned = 0;

        for entry in WalkDir::new(&self.root_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip directories and non-text files
            if !path.is_file() || !self.should_scan(path) {
                continue;
            }

            files_scanned += 1;

            if let Ok(content) = fs::read_to_string(path) {
                let file_issues = self.scan_file(path, &content, verbose);
                issues.extend(file_issues);
            }
        }

        Ok(Report::new(issues, files_scanned))
    }

    fn should_scan(&self, path: &Path) -> bool {
        // Skip common directories
        let path_str = path.to_string_lossy();
        if path_str.contains("/node_modules/")
            || path_str.contains("/target/")
            || path_str.contains("/.git/")
            || path_str.contains("/dist/")
            || path_str.contains("/build/")
        {
            return false;
        }

        // Only scan text files
        if let Some(ext) = path.extension() {
            let ext = ext.to_string_lossy().to_lowercase();
            matches!(
                ext.as_str(),
                "rs" | "js" | "ts" | "jsx" | "tsx" | "py" | "go" | "java" | "c" | "cpp" | "h"
                    | "hpp" | "cs" | "php" | "rb" | "swift" | "kt" | "scala" | "sh" | "bash"
                    | "env" | "yml" | "yaml" | "json" | "toml" | "sql"
            )
        } else {
            false
        }
    }

    fn scan_file(&self, path: &Path, content: &str, verbose: bool) -> Vec<Issue> {
        let mut issues = Vec::new();
        let relative_path = path
            .strip_prefix(&self.root_path)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        // Scan with built-in patterns
        for pattern in PATTERNS.iter() {
            // Skip low severity if not verbose
            if !verbose && pattern.severity == Severity::Low {
                continue;
            }

            for (line_num, line) in content.lines().enumerate() {
                if let Some(captures) = pattern.regex.captures(line) {
                    let matched = captures.get(0).map(|m| m.as_str()).unwrap_or("");

                    issues.push(Issue {
                        severity: pattern.severity.clone(),
                        title: pattern.title.to_string(),
                        file: relative_path.clone(),
                        line: line_num + 1,
                        code: line.trim().to_string(),
                        matched: matched.to_string(),
                        description: pattern.description.to_string(),
                        fix_suggestion: Some(pattern.fix_suggestion.to_string()),
                        risk_score: pattern.severity.score(),
                    });
                }
            }
        }

        // Scan with custom rules
        for rule in &self.custom_rules {
            if !verbose && rule.severity == Severity::Low {
                continue;
            }

            for (line_num, line) in content.lines().enumerate() {
                if let Some(captures) = rule.regex.captures(line) {
                    let matched = captures.get(0).map(|m| m.as_str()).unwrap_or("");

                    issues.push(Issue {
                        severity: rule.severity.clone(),
                        title: rule.title.clone(),
                        file: relative_path.clone(),
                        line: line_num + 1,
                        code: line.trim().to_string(),
                        matched: matched.to_string(),
                        description: rule.description.clone(),
                        fix_suggestion: Some(rule.fix_suggestion.clone()),
                        risk_score: rule.severity.score(),
                    });
                }
            }
        }

        issues
    }
}
