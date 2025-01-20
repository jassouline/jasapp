import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0016(BaseRule):
    """
    Rule to detect if the `PYTHONHTTPSVERIFY` environment variable is set to `0`,
    disabling HTTPS certificate verification.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="PythonHTTPSVerifyDisabled",
            name="SEC0016",
            description="`PYTHONHTTPSVERIFY` environment variable is set to `0`, disabling HTTPS certificate verification.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if the `PYTHONHTTPSVERIFY` environment variable is set to `0` in `ENV` instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "ENV":
                if self.is_python_https_verify_disabled(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`PYTHONHTTPSVERIFY` environment variable is set to `0`, "
                                   "disabling HTTPS certificate verification.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_python_https_verify_disabled(self, arguments):
        """
        Checks if the `PYTHONHTTPSVERIFY` environment variable is set to `0` in an `ENV` instruction's arguments.

        Args:
            arguments (str): The arguments of the `ENV` instruction.

        Returns:
            bool: True if `PYTHONHTTPSVERIFY` is set to `0`, False otherwise.
        """
        for pair in arguments.split():
            if "=" in pair:
                key, value = pair.split("=", 1)
                if key.strip() == "PYTHONHTTPSVERIFY" and value.strip().strip("'\"") == "0":
                    return True
        return False


@pytest.fixture
def python_https_verify_disabled():
    return SEC0016()


def test_python_https_verify_disabled_detects_disabled_verification(python_https_verify_disabled):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "PYTHONHTTPSVERIFY=0"},
    ]
    errors = python_https_verify_disabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "PYTHONHTTPSVERIFY` environment variable is set to `0`" in errors[0]["message"]


def test_python_https_verify_disabled_allows_enabled_verification(python_https_verify_disabled):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "PYTHONHTTPSVERIFY=1"},
    ]
    errors = python_https_verify_disabled.check(parsed_content)
    assert len(errors) == 0


def test_python_https_verify_disabled_ignores_other_instructions(python_https_verify_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = python_https_verify_disabled.check(parsed_content)
    assert len(errors) == 0
