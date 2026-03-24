use regex::Regex;
use crate::report::Severity;

pub struct Pattern {
    pub title: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub regex: Regex,
}

lazy_static::lazy_static! {
    pub static ref PATTERNS: Vec<Pattern> = vec![
        // Hardcoded API Keys
        Pattern {
            title: "Hardcoded API Key",
            description: "API key found in source code. Store in environment variables instead.",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["']([a-zA-Z0-9_\-]{20,})["']"#).unwrap(),
        },
        
        // AWS Keys
        Pattern {
            title: "AWS Access Key",
            description: "AWS access key found. Never commit AWS credentials.",
            severity: Severity::High,
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        },
        
        // Private Keys
        Pattern {
            title: "Private Key",
            description: "Private key found in source code. This is a critical security risk.",
            severity: Severity::High,
            regex: Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
        },
        
        // Generic Secrets
        Pattern {
            title: "Hardcoded Secret",
            description: "Secret or password found in source code.",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*["']([^"'\s]{8,})["']"#).unwrap(),
        },
        
        // SQL Injection
        Pattern {
            title: "SQL Injection Risk",
            description: "String concatenation in SQL query. Use parameterized queries.",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*["']"#).unwrap(),
        },
        
        // Insecure HTTP
        Pattern {
            title: "Insecure HTTP Connection",
            description: "Using HTTP instead of HTTPS. Data transmitted in plain text.",
            severity: Severity::Medium,
            regex: Regex::new(r#"http://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}"#).unwrap(),
        },
        
        // Eval usage
        Pattern {
            title: "Dangerous eval() Usage",
            description: "eval() can execute arbitrary code. Avoid if possible.",
            severity: Severity::High,
            regex: Regex::new(r"\beval\s*\(").unwrap(),
        },
        
        // Hardcoded IPs
        Pattern {
            title: "Hardcoded IP Address",
            description: "IP address in source code. Use configuration files.",
            severity: Severity::Low,
            regex: Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap(),
        },
        
        // JWT Secrets
        Pattern {
            title: "Hardcoded JWT Secret",
            description: "JWT secret in source code. Store in environment variables.",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)jwt[_-]?secret\s*[=:]\s*["']([^"'\s]{8,})["']"#).unwrap(),
        },
        
        // Database URLs
        Pattern {
            title: "Database Connection String",
            description: "Database URL with credentials. Use environment variables.",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)(postgres|mysql|mongodb)://[^:]+:[^@]+@"#).unwrap(),
        },
    ];
}
