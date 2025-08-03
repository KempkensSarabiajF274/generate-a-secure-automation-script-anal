use std::collections::HashMap;
use std::fs;

struct AutomationScriptAnalyzer {
    script_path: String,
    allowed_functions: HashMap<String, Vec<String>>,
    sensitive_data_regex: Vec<String>,
}

impl AutomationScriptAnalyzer {
    fn new(script_path: String) -> AutomationScriptAnalyzer {
        AutomationScriptAnalyzer {
            script_path,
            allowed_functions: HashMap::new(),
            sensitive_data_regex: Vec::new(),
        }
    }

    fn add_allowed_function(&mut self, function_name: String, allowed_args: Vec<String>) {
        self.allowed_functions.insert(function_name, allowed_args);
    }

    fn add_sensitive_data_regex(&mut self, regex: String) {
        self.sensitive_data_regex.push(regex);
    }

    fn analyze_script(&self) {
        let script_content = fs::read_to_string(self.script_path.clone()).unwrap();
        let script_lines: Vec<&str> = script_content.split("\n").collect();

        for line in script_lines {
            // Check for allowed functions
            for (function_name, allowed_args) in &self.allowed_functions {
                if line.contains(function_name) {
                    let args: Vec<_> = line.split_whitespace().skip(1).collect();
                    if !allowed_args.iter().any(|arg| args.contains(arg)) {
                        println!("Warning: {} function has unauthorized argument", function_name);
                    }
                }
            }

            // Check for sensitive data
            for regex in &self.sensitive_data_regex {
                if line.contains(regex) {
                    println!("Warning: Sensitive data detected in script");
                }
            }
        }
    }
}

fn main() {
    let mut analyzer = AutomationScriptAnalyzer::new("path/to/script.txt".to_string());
    analyzer.add_allowed_function("echo".to_string(), vec!["hello".to_string(), "world".to_string()]);
    analyzer.add_sensitive_data_regex("password.*".to_string());
    analyzer.analyze_script();
}