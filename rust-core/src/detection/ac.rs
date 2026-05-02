use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub pattern: String,
    pub severity: Severity,
    pub action: Action,
    pub proto: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Action {
    Block,
    Alert,
    LogOnly,
}

pub struct AhoCorasickMatcher {
    automaton: AhoCorasick,
    rules: Vec<Rule>,
    pattern_to_rule: HashMap<usize, usize>,
}

impl AhoCorasickMatcher {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let mut patterns = Vec::new();
        let mut rules = Vec::new();
        let mut pattern_to_rule = HashMap::new();
        
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            
            if let Ok(rule) = Self::parse_rule_line(&line) {
                let pattern_idx = patterns.len();
                patterns.push(rule.pattern.clone());
                pattern_to_rule.insert(pattern_idx, rules.len());
                rules.push(rule);
            }
        }
        
        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)?;
        
        Ok(Self {
            automaton,
            rules,
            pattern_to_rule,
        })
    }
    
    fn parse_rule_line(line: &str) -> Result<Rule, Box<dyn std::error::Error>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut rule = Rule {
            id: String::new(),
            pattern: String::new(),
            severity: Severity::Medium,
            action: Action::Alert,
            proto: None,
        };
        
        for part in parts {
            if part.contains("sid:") {
                rule.id = part.replace("sid:", "").to_string();
            } else if part.contains("content:") {
                let content = part.replace("content:\"", "").replace("\";", "");
                rule.pattern = content;
            } else if part.contains("severity:") {
                match part.replace("severity:", "").as_str() {
                    "critical" => rule.severity = Severity::Critical,
                    "high" => rule.severity = Severity::High,
                    "medium" => rule.severity = Severity::Medium,
                    "low" => rule.severity = Severity::Low,
                    _ => {}
                }
            } else if part.contains("action:") {
                match part.replace("action:", "").as_str() {
                    "block" => rule.action = Action::Block,
                    "alert" => rule.action = Action::Alert,
                    _ => {}
                }
            }
        }
        
        Ok(rule)
    }
    
    pub fn search(&self, data: &[u8]) -> Vec<&Rule> {
        let mut matched = Vec::new();
        let data_str = String::from_utf8_lossy(data);
        
        for mat in self.automaton.find_iter(&data_str) {
            if let Some(&rule_idx) = self.pattern_to_rule.get(&mat.pattern()) {
                matched.push(&self.rules[rule_idx]);
            }
        }
        
        matched
    }
}
