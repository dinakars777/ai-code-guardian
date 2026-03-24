use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::report::Severity;

#[derive(Debug, Serialize, Deserialize)]
pub struct CustomRule {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub pattern: String,
    pub fix_suggestion: String,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub regex: Regex,
    pub fix_suggestion: String,
}

pub fn load_custom_rules(path: &Path) -> Result<Vec<CompiledRule>> {
    let rules_file = path.join(".guardian.rules.json");
    
    if !rules_file.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&rules_file)
        .context("Failed to read custom rules file")?;
    
    let rules: Vec<CustomRule> = serde_json::from_str(&content)
        .context("Failed to parse custom rules JSON")?;

    let mut compiled = Vec::new();
    for rule in rules {
        let severity = match rule.severity.to_lowercase().as_str() {
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => {
                eprintln!("Warning: Invalid severity '{}' in rule '{}', defaulting to Medium", 
                    rule.severity, rule.title);
                Severity::Medium
            }
        };

        match Regex::new(&rule.pattern) {
            Ok(regex) => {
                compiled.push(CompiledRule {
                    title: rule.title,
                    description: rule.description,
                    severity,
                    regex,
                    fix_suggestion: rule.fix_suggestion,
                });
            }
            Err(e) => {
                eprintln!("Warning: Invalid regex pattern in rule '{}': {}", rule.title, e);
            }
        }
    }

    Ok(compiled)
}
