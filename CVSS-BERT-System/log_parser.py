import re
import json
import urllib.parse
from datetime import datetime

class LogParser:
    def __init__(self):
        # Common Log Format (CLF) and Combined Log Format regex
        self.web_log_pattern = re.compile(
            r'^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+)\s*(\S+)?\s*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"'
        )
        # SSH Failed Login regex
        self.ssh_fail_pattern = re.compile(
            r'Failed password for (invalid user )?(\S+) from (\S+) port \d+ ssh2'
        )
        
        # Basic attack signatures for semantic enhancement
        self.attack_signatures = [
            (r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|'|\"|%27|%22)", "SQL Injection"),
            (r"(?i)(<script>|javascript:|onerror=|onload=|eval\(|alert\()", "Cross-Site Scripting (XSS)"),
            (r"(?i)(\.\./|\.\.%2f|/etc/passwd|c:\\windows\\system32)", "Path Traversal"),
            (r"(?i)(;\s*ls|\|\s*cat|`|system\(|exec\()", "Command Injection"),
            (r"(?i)(\$\{jndi:|\$\{java:)", "Log4j Remote Code Execution"),
        ]

    def parse_log(self, log_line):
        """
        Parse a single log line and return structured data + semantic description.
        """
        log_line = log_line.strip()
        if not log_line:
            return None

        parsed_data = {}
        
        # 1. Try Parsing as JSON
        if log_line.startswith('{') and log_line.endswith('}'):
            try:
                data = json.loads(log_line)
                parsed_data = {
                    "type": "JSON",
                    "timestamp": data.get("timestamp", datetime.now().isoformat()),
                    "source_ip": data.get("client_ip", data.get("ip", "Unknown")),
                    "payload": str(data),
                    "raw": log_line
                }
                # Construct description from JSON fields if possible
                msg = data.get("message", "")
                url = data.get("url", "")
                parsed_data["description"] = f"Application log event: {msg} {url}"
                return self._enhance_description(parsed_data)
            except json.JSONDecodeError:
                pass

        # 2. Try Parsing as Web Log (Nginx/Apache)
        match = self.web_log_pattern.match(log_line)
        if match:
            groups = match.groups()
            parsed_data = {
                "type": "Web Server (Nginx/Apache)",
                "source_ip": groups[0],
                "timestamp": groups[1],
                "method": groups[2],
                "url": groups[3],
                "protocol": groups[4],
                "status_code": groups[5],
                "size": groups[6],
                "referer": groups[7],
                "user_agent": groups[8],
                "raw": log_line
            }
            
            # Decode URL for analysis
            decoded_url = urllib.parse.unquote(parsed_data["url"])
            parsed_data["decoded_payload"] = decoded_url
            
            # Generate initial description
            parsed_data["description"] = f"Web request from {parsed_data['source_ip']} accessing {decoded_url} with status {parsed_data['status_code']}."
            return self._enhance_description(parsed_data)

        # 3. Try Parsing as SSH Log
        match = self.ssh_fail_pattern.search(log_line)
        if match:
            groups = match.groups()
            user = groups[1]
            ip = groups[2]
            parsed_data = {
                "type": "SSH System Log",
                "source_ip": ip,
                "user": user,
                "event": "Failed Login",
                "raw": log_line,
                "description": f"Multiple failed SSH login attempts detected from {ip} for user {user}, indicating potential Brute Force attack."
            }
            return parsed_data

        # 4. Fallback for generic logs
        parsed_data = {
            "type": "Generic/Unknown",
            "raw": log_line,
            "source_ip": "Unknown",
            "description": f"Suspicious log activity detected: {log_line[:200]}"
        }
        return self._enhance_description(parsed_data)

    def _enhance_description(self, data):
        """
        Analyze payload and enhance the text description for the BERT model.
        """
        payload = data.get("decoded_payload", data.get("raw", ""))
        
        detected_attacks = []
        for pattern, attack_name in self.attack_signatures:
            if re.search(pattern, payload):
                detected_attacks.append(attack_name)
        
        if detected_attacks:
            attacks_str = ", ".join(detected_attacks)
            # Create a strong vulnerability description for the model
            data["description"] = f"Cyber attack detected: {attacks_str}. The attacker from {data.get('source_ip')} sent a malicious payload containing '{payload[:50]}...' targeting the server. This allows {attacks_str}."
            data["is_attack"] = True
            data["attack_types"] = detected_attacks
        else:
            data["is_attack"] = False
            
        return data
