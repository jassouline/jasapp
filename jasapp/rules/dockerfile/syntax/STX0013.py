import pytest
from jasapp.rules.base_rule import BaseRule


class STX0013(BaseRule):
    """
    Rule to ensure versions are pinned when using pip install.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="PinPipVersions",
            hadolint="DL3013",
            name="STX0013",
            description=(
                "Pin versions in pip install. Instead of `pip install <package>` use "
                "`pip install <package>==<version>` or `pip install --requirement <requirements file>`."
            ),
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `pip install` commands pin the versions of installed packages.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = self.split_commands(instr["arguments"])
                for command in commands:
                    if self.is_pip_install(command) and not self.is_version_pinned(command):
                        errors.append({
                            "line": instr["line"],
                            "message": (
                                "Pin versions in pip. Instead of `pip install <package>` use "
                                "`pip install <package>==<version>` or `pip install --requirement <requirements file>`."
                            ),
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })
        return errors

    @staticmethod
    def split_commands(arguments):
        """
        Split a multi-line RUN instruction into individual commands.

        Args:
            arguments (str): The RUN instruction arguments.

        Returns:
            list: A list of individual commands.
        """
        commands = arguments.replace("\\\n", " ").split("&&")
        return [cmd.strip() for cmd in commands]

    @staticmethod
    def is_pip_install(command):
        """
        Check if a command is a `pip install` command.

        Args:
            command (str): The command to check.

        Returns:
            bool: True if the command is a `pip install` command, False otherwise.
        """
        return command.startswith("pip install") and not (
            "--requirement" in command or "-r" in command
        )

    @staticmethod
    def is_version_pinned(command):
        """
        Check if a `pip install` command pins versions for all packages.

        Args:
            command (str): The `pip install` command to check.

        Returns:
            bool: True if all packages in the command are version-pinned, False otherwise.
        """
        packages = command.replace("pip install", "").split()
        version_symbols = {"==", ">=", "<=", ">", "<", "!=", "~=", "==="}
        for package in packages:
            if not any(symbol in package for symbol in version_symbols):
                return False
        return True


@pytest.fixture
def pin_pip_install_versions():
    return STX0013()


# Tests for unpinned packages
def test_pin_pip_install_versions_detects_unpinned_packages(pin_pip_install_versions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pip install flask"},
        {"line": 2, "instruction": "RUN", "arguments": "pip install requests matplotlib"},
    ]
    errors = pin_pip_install_versions.check(parsed_content)
    assert len(errors) == 2


# Tests for pinned packages
def test_pin_pip_install_versions_allows_pinned_packages(pin_pip_install_versions):
    parsed_content = [
        {"line": 3, "instruction": "RUN", "arguments": "pip install flask==2.0.1"},
        {"line": 4, "instruction": "RUN", "arguments": "pip install requests>=2.25 matplotlib<3.5"},
    ]
    errors = pin_pip_install_versions.check(parsed_content)
    assert len(errors) == 0


# Test ignoring requirements files
def test_pin_pip_install_versions_ignores_requirements_file(pin_pip_install_versions):
    parsed_content = [
        {"line": 5, "instruction": "RUN", "arguments": "pip install -r requirements.txt"},
        {"line": 6, "instruction": "RUN", "arguments": "pip install --requirement requirements.txt"},
    ]
    errors = pin_pip_install_versions.check(parsed_content)
    assert len(errors) == 0


# Tests for mixed arguments
def test_pin_pip_install_versions_mixed_arguments(pin_pip_install_versions):
    parsed_content = [
        {"line": 7, "instruction": "RUN", "arguments": "pip install flask==2.0.1 requests"},
    ]
    errors = pin_pip_install_versions.check(parsed_content)
    assert len(errors) == 1


# Tests for flags without pinning
def test_pin_pip_install_versions_detects_flags_without_pinning(pin_pip_install_versions):
    parsed_content = [
        {"line": 8, "instruction": "RUN", "arguments": "pip install --no-cache-dir flask"},
    ]
    errors = pin_pip_install_versions.check(parsed_content)
    assert len(errors) == 1


# Tests for multi-line commands
def test_pin_pip_install_versions_handles_multiline_commands(pin_pip_install_versions):
    parsed_content = [
        {"line": 9, "instruction": "RUN", "arguments": "pip install flask==2.0.1 \\\n    requests==2.25.1"},
    ]
    errors = pin_pip_install_versions.check(parsed_content)
    assert len(errors) == 0
