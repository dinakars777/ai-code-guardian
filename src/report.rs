use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub title: String,
    pub file: String,
    pub line: usize,
    pub code: String,
    pub matched: String,
    pub description: String,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub issues: Vec<Issue>,
    pub files_scanned: usize,
}

impl Report {
    pub fn new(issues: Vec<Issue>, files_scanned: usize) -> Self {
        Self {
            issues,
            files_scanned,
        }
    }

    pub fn has_high_risk_issues(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == Severity::High)
    }

    pub fn print(&self) {
        if self.issues.is_empty() {
            println!("{}", "✅ No security issues found!".green().bold());
            println!();
            println!("Scanned {} files", self.files_scanned);
            return;
        }

        // Group by severity
        let high: Vec<_> = self
            .issues
            .iter()
            .filter(|i| i.severity == Severity::High)
            .collect();
        let medium: Vec<_> = self
            .issues
            .iter()
            .filter(|i| i.severity == Severity::Medium)
            .collect();
        let low: Vec<_> = self
            .issues
            .iter()
            .filter(|i| i.severity == Severity::Low)
            .collect();

        // Print high severity issues
        for issue in &high {
            self.print_issue(issue, "HIGH", Color::Red);
        }

        // Print medium severity issues
        for issue in &medium {
            self.print_issue(issue, "MEDIUM", Color::Yellow);
        }

        // Print low severity issues
        for issue in &low {
            self.print_issue(issue, "LOW", Color::Blue);
        }

        println!();
        println!(
            "{}",
            format!(
                "Scan complete: {} issues found ({} high, {} medium, {} low)",
                self.issues.len(),
                high.len(),
                medium.len(),
                low.len()
            )
            .bold()
        );
        println!("Scanned {} files", self.files_scanned);
    }

    fn print_issue(&self, issue: &Issue, severity_label: &str, color: Color) {
        println!(
            "{} {}: {}",
            "❌".color(color),
            severity_label.color(color).bold(),
            issue.title.bold()
        );
        println!(
            "   {}: {}:{}",
            "File".dimmed(),
            issue.file,
            issue.line
        );
        println!("   {}: {}", "Code".dimmed(), issue.code.dimmed());
        if !issue.matched.is_empty() && issue.matched != issue.code {
            println!("   {}: {}", "Match".dimmed(), issue.matched.yellow());
        }
        println!("   {}: {}", "Risk".dimmed(), issue.description);
        
        // Print fix suggestion if available
        if let Some(fix) = &issue.fix_suggestion {
            println!("   {}: {}", "Fix".green().bold(), fix.green());
        }
        
        println!();
    }
}
