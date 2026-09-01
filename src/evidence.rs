use crate::report::Evidence;

pub fn generate_sql_injection_proof(_code_line: &str) -> Evidence {
    Evidence::new(
        "# Reproduction: SQL injection via f-string\n\
         import sqlite3\n\
         conn = sqlite3.connect(':memory:')\n\
         conn.execute('CREATE TABLE users (id INT, name TEXT)')\n\
         conn.execute(\"INSERT INTO users VALUES (1, 'admin')\")\n\
         # This is what the vulnerable code does:\n\
         user_id = \"1 OR 1=1\"\n\
         query = f\"SELECT * FROM users WHERE id = {{user_id}}\"\n\
         # Returns ALL rows instead of just the target user\n\
         result = conn.execute(query).fetchall()\n\
         assert len(result) > 1, 'Injection succeeded: returned multiple rows'"
            .to_string(),
        "Query should return only the specific user matching the ID".to_string(),
        "F-string interpolation allows arbitrary SQL — attacker can inject 'OR 1=1' to extract all rows".to_string(),
        "behavioral".to_string(),
    )
}

pub fn generate_shell_injection_proof(_code_line: &str) -> Evidence {
    Evidence::new(
        "# Reproduction: shell=True command injection\n\
         import subprocess\n\
         # Attacker-controlled input:\n\
         user_input = 'legitimate_cmd; cat /etc/passwd'\n\
         # Vulnerable call:\n\
         result = subprocess.run(user_input, shell=True, capture_output=True)\n\
         # shell=True interprets semicolons — attacker runs arbitrary commands\n\
         assert b'root:' in result.stdout or b'root:' in result.stderr"
            .to_string(),
        "Command should only execute the intended command".to_string(),
        "shell=True interprets shell metacharacters (;, |, &&, etc.) allowing arbitrary command execution".to_string(),
        "behavioral".to_string(),
    )
}

pub fn generate_eval_exec_proof(_code_line: &str, func: &str) -> Evidence {
    Evidence::new(
        format!(
            "# Reproduction: {func}() code injection\n\
             # Attacker-controlled input:\n\
             malicious_input = '__import__(\"os\").system(\"id\")'\n\
             # Vulnerable call:\n\
             result = {func}(malicious_input)\n\
             # Attacker can execute arbitrary Python code"
        ),
        format!("{func} should not execute arbitrary code from untrusted input"),
        format!("{func}() evaluates/executes arbitrary Python — attacker can run any system command"),
        "behavioral".to_string(),
    )
}

pub fn generate_secret_proof(_code_line: &str, name: &str) -> Evidence {
    Evidence::new(
        format!(
            "# Reproduction: Hardcoded secret exposure\n\
             # The secret is visible in source code:\n\
             {name} = \"my_secret_value_12345\"\n\
             # Anyone with repo access can read it:\n\
             import ast\n\
             with open(__file__) as f:\n\
                 tree = ast.parse(f.read())\n\
             for node in ast.walk(tree):\n\
                 if isinstance(node, ast.Assign):\n\
                     for target in node.targets:\n\
                         if isinstance(target, ast.Name) and '{name}' in target.id.lower():\n\
                             print(f'Found secret: {{target.id}}')\n\
             # Secret is extractable from source — not secure"
        ),
        "Secrets should not be visible in source code".to_string(),
        "Hardcoded secrets are readable by anyone with repository access".to_string(),
        "static-analysis".to_string(),
    )
}

pub fn generate_resource_leak_proof(_code_line: &str, var_name: &str) -> Evidence {
    Evidence::new(
        format!(
            "# Reproduction: Resource leak without context manager\n\
             import os\n\
             # Simulating the leaked resource:\n\
             f = open('/dev/null', 'r')\n\
             # Without 'with' or explicit .close(), the file descriptor leaks\n\
             # In long-running processes, this exhausts OS file descriptor limits\n\
             # Fix: use 'with open(...) as {var_name}:'"
        ),
        "File should be closed after use to free OS resources".to_string(),
        "Without context manager, file descriptor leaks accumulate and can crash long-running processes".to_string(),
        "behavioral".to_string(),
    )
}

pub fn generate_mutable_default_proof(_code_line: &str) -> Evidence {
    Evidence::new(
        "# Reproduction: Mutable default argument bug\n\
         def append_to(item, target=[]):\n\
             target.append(item)\n\
             return target\n\
         # First call — seems fine:\n\
         result1 = append_to(1)\n\
         assert result1 == [1]\n\
         # Second call — bug! Default list persists:\n\
         result2 = append_to(2)\n\
         assert result2 == [2]  # FAIL: actually [1, 2]\n\
         # The default [] is shared across ALL calls"
            .to_string(),
        "Each call should get a fresh empty list".to_string(),
        "Mutable default arguments are created once at function definition time, not per call".to_string(),
        "behavioral".to_string(),
    )
}

pub fn generate_except_pass_proof(_code_line: &str) -> Evidence {
    Evidence::new(
        "# Reproduction: Silent exception swallowing\n\
         def risky_operation():\n\
             try:\n\
                 result = 1 / 0\n\
             except Exception:\n\
                 pass  # Silently swallowed!\n\
         # The function appears to succeed but actually failed:\n\
         result = risky_operation()\n\
         assert result is None  # Caller has no idea something went wrong\n\
         # Bugs hide because exceptions are silently consumed"
            .to_string(),
        "Exceptions should be logged or propagated so failures are visible".to_string(),
        "except: pass hides errors — bugs become invisible and hard to debug".to_string(),
        "behavioral".to_string(),
    )
}
