import re
import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0006(BaseRule):
    """
    Rule to detect hardcoded secrets in `ENV`, `ARG`, or `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="HardcodedSecrets",
            name="SEC0006",
            description="Hardcoded secrets found in `ENV`, `ARG`, or `RUN` instruction.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks for hardcoded secrets in `ENV`, `ARG`, or `RUN` instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        # Regular expression to detect potential secrets (customize as needed)
        secret_patterns = [
            re.compile(r"password\s*[:=]\s*.+", re.IGNORECASE),  # Matches "password :" or "password=" followed by any characters
            re.compile(r"api_?key\s*[:=]\s*.+", re.IGNORECASE),  # Matches "api_key :", "api-key:", "apikey =", "api-key =" followed by any characters
            re.compile(r"secret\s*[:=]\s*.+", re.IGNORECASE),  # Matches "secret :" or "secret=" followed by any characters
            re.compile(r"token\s*[:=]\s*.+", re.IGNORECASE),  # Matches "token :" or "token=" followed by any characters
            re.compile(r"access_?key\s*[:=]\s*.+", re.IGNORECASE),  # Matches "access_key :", "access-key:", "accesskey =", "access-key =" followed by any characters
            re.compile(r"-----BEGIN [A-Z]+ PRIVATE KEY-----"),  # Matches PEM private key headers
            # Add more patterns as needed
            re.compile(r"['\"][a-zA-Z0-9\-\_\.\+\=]{20,}['\"]"),  # Matches strings with at least 20 alphanumeric characters, hyphens, underscores, dots, plus or equal signs, enclosed in single or double quotes
            re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE),  # Matches UUIDs
            re.compile(r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),  # Matches IP addresses
        ]

        for instr in instructions:
            if instr["instruction"] in ["ENV", "ARG", "RUN"]:
                arguments = instr["arguments"]
                for pattern in secret_patterns:
                    if pattern.search(arguments):
                        errors.append({
                            "line": instr["line"],
                            "message": f"Hardcoded secret found in '{instr['instruction']}' instruction.",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })
                        break  # Avoid reporting multiple errors for the same line if multiple patterns match

        return errors


@pytest.fixture
def hardcoded_secrets():
    return SEC0006()


def test_hardcoded_secrets_detects_secrets_in_env(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "API_KEY=your_secret_api_key"},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_detects_secrets_in_arg(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "ARG", "arguments": "PASSWORD=secret_password"},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_detects_secrets_in_run(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo DATABASE_TOKEN=your_database_token"},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_allows_non_secrets(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=some_value"},
        {"line": 2, "instruction": "ARG", "arguments": "DEBUG=true"},
        {"line": 3, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 0


def test_hardcoded_secrets_pem_key(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "-----BEGIN RSA PRIVATE KEY-----"}
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_detects_secrets_in_env_with_quotes(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "API_KEY='your_secret_api_key'"},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_detects_secrets_in_arg_with_quotes(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "ARG", "arguments": "PASSWORD=\"secret_password\""},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_detects_secrets_in_run_with_quotes(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo DATABASE_TOKEN=\"your_database_token\""},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_detects_long_string(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "LONG_STRING='ThisIsALongStringThatMightBeASecret'"},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_detects_uuid(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "UUID='a1b2c3d4-e5f6-11e8-9f32-f2801f1b9fd1'"},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]


def test_hardcoded_secrets_detects_ip_address(hardcoded_secrets):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "IP_ADDRESS=192.168.1.1"},
    ]
    errors = hardcoded_secrets.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Hardcoded secret found" in errors[0]["message"]
