import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0020(BaseRule):
    """
    Rule to detect if the `yum` package manager is configured to skip GPG signature checks in `RUN` instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="YumSkipGPGCheck",
            name="SEC0020",
            description="`yum` is configured to skip GPG signature checks.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `yum` commands in `RUN` instructions are configured to skip GPG signature checks.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                if self.is_yum_skipping_gpg_check(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`yum` is configured to skip GPG signature checks. "
                                   "Use `gpgcheck=1` in the `yum` configuration or remove `--nogpgcheck` from commands.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_yum_skipping_gpg_check(self, command_string):
        """
        Checks if a command string contains a `yum` command that skips GPG signature checks.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if `yum` is configured to skip GPG checks, False otherwise.
        """
        if "yum" not in command_string:
            return False

        # Check for --nogpgcheck flag
        if "--nogpgcheck" in command_string:
            return True

        # Check for gpgcheck=0 in the command (less common, but possible)
        if "gpgcheck=0" in command_string:
            return True

        return False


@pytest.fixture
def yum_skipping_gpg_check():
    return SEC0020()


def test_yum_gpg_check_detects_nogpgcheck(yum_skipping_gpg_check):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install --nogpgcheck httpd"},
    ]
    errors = yum_skipping_gpg_check.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`yum` is configured to skip GPG signature checks" in errors[0]["message"]


def test_yum_gpg_check_detects_gpgcheck_0(yum_skipping_gpg_check):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install httpd --setopt=gpgcheck=0"},
    ]
    errors = yum_skipping_gpg_check.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`yum` is configured to skip GPG signature checks" in errors[0]["message"]


def test_yum_gpg_check_allows_secure_yum(yum_skipping_gpg_check):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "yum install httpd"},
    ]
    errors = yum_skipping_gpg_check.check(parsed_content)
    assert len(errors) == 0


def test_yum_gpg_check_ignores_other_instructions(yum_skipping_gpg_check):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = yum_skipping_gpg_check.check(parsed_content)
    assert len(errors) == 0
