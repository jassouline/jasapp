import pytest
from jasapp.rules.base_rule import BaseRule


class STX0007(BaseRule):
    """
    Rule to ensure that versions are pinned in `apt-get install` commands.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="PinAptGetVersions",
            hadolint="DL3008",
            name="STX0007",
            description="Ensure versions are pinned in `apt-get install` commands to prevent unpredictable behavior.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Check if `apt-get install` commands pin package versions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = instr["arguments"].split("&&")
                for cmd in commands:
                    cmd_parts = cmd.strip().split()
                    if cmd_parts[:2] == ["apt-get", "install"]:
                        packages = [
                            pkg for pkg in cmd_parts[2:]
                            if not pkg.startswith("-") and "=" not in pkg and not pkg.endswith(".deb") and "/" not in pkg
                        ]
                        for pkg in packages:
                            errors.append({
                                "line": instr["line"],
                                "message": f"Pin versions in `apt-get install`. Use `apt-get install <package>=<version>` instead of `{pkg}`.",
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })
        return errors


@pytest.fixture
def pin_apt_get_versions():
    return STX0007()


def test_pin_apt_get_versions_detects_unpinned_packages(pin_apt_get_versions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get install curl vim -y"},
        {"line": 2, "instruction": "RUN", "arguments": "apt-get install nano"},
    ]
    errors = pin_apt_get_versions.check(parsed_content)
    assert len(errors) == 3
    assert errors[0]["message"] == "Pin versions in `apt-get install`. Use `apt-get install <package>=<version>` instead of `curl`."
    assert errors[1]["message"] == "Pin versions in `apt-get install`. Use `apt-get install <package>=<version>` instead of `vim`."
    assert errors[2]["message"] == "Pin versions in `apt-get install`. Use `apt-get install <package>=<version>` instead of `nano`."


def test_pin_apt_get_versions_allows_pinned_packages(pin_apt_get_versions):
    parsed_content = [
        {"line": 3, "instruction": "RUN", "arguments": "apt-get install curl=7.68.0 vim=8.2.2434-1 -y"},
        {"line": 4, "instruction": "RUN", "arguments": "apt-get install nano=5.4-1"},
    ]
    errors = pin_apt_get_versions.check(parsed_content)
    assert len(errors) == 0


def test_pin_apt_get_versions_allows_local_deb_packages(pin_apt_get_versions):
    parsed_content = [
        {"line": 5, "instruction": "RUN", "arguments": "apt-get install ./local-package.deb -y"},
    ]
    errors = pin_apt_get_versions.check(parsed_content)
    assert len(errors) == 0
