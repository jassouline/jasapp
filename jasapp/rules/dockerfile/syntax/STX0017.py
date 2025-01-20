import pytest
from jasapp.rules.base_rule import BaseRule


class STX0017(BaseRule):
    """
    Rule to ensure versions are pinned when using apk add.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="PinApkVersions",
            hadolint="DL3018",
            name="STX0017",
            description=(
                "Pin versions in apk add. Instead of `apk add <package>` use `apk add <package>=<version>`."
            ),
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `apk add` commands pin the versions of installed packages.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "RUN":
                commands = self.normalize_commands(instr["arguments"])
                for command in commands:
                    if self.is_apk_add(command) and not self.are_versions_pinned(command):
                        errors.append({
                            "line": instr["line"],
                            "message": (
                                "Pin versions in apk add. Instead of `apk add <package>` use "
                                "`apk add <package>=<version>`."
                            ),
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })
        return errors

    @staticmethod
    def normalize_commands(arguments):
        """
        Normalize multi-line commands by replacing continuation characters.

        Args:
            arguments (str): The command string to normalize.

        Returns:
            list: A list of individual commands.
        """
        normalized = arguments.replace("\\\n", " ")
        return [cmd.strip() for cmd in normalized.split("&&")]

    @staticmethod
    def is_apk_add(command):
        """
        Check if a command is an `apk add` command.

        Args:
            command (str): The command to check.

        Returns:
            bool: True if the command is an `apk add` command, False otherwise.
        """
        return command.startswith("apk add")

    @staticmethod
    def are_versions_pinned(command):
        """
        Check if all packages in an `apk add` command have pinned versions.

        Args:
            command (str): The `apk add` command to check.

        Returns:
            bool: True if all packages in the command are version-pinned, False otherwise.
        """
        packages = command.replace("apk add", "").split()
        for package in packages:
            if not (STX0017.is_version_fixed(package) or STX0017.is_package_file(package)):
                return False
        return True

    @staticmethod
    def is_version_fixed(package):
        """
        Check if a package has a fixed version.

        Args:
            package (str): The package name.

        Returns:
            bool: True if the package has a fixed version, False otherwise.
        """
        return "=" in package

    @staticmethod
    def is_package_file(package):
        """
        Check if a package is provided as a file.

        Args:
            package (str): The package name.

        Returns:
            bool: True if the package is a file, False otherwise.
        """
        return package.endswith(".apk")


@pytest.fixture
def pin_apk_add_versions():
    return STX0017()


def test_pin_apk_add_versions_detects_unpinned_packages(pin_apk_add_versions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apk add bash"},
        {"line": 2, "instruction": "RUN", "arguments": "apk add curl vim"},
    ]
    errors = pin_apk_add_versions.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert errors[1]["line"] == 2


def test_pin_apk_add_versions_allows_pinned_packages(pin_apk_add_versions):
    parsed_content = [
        {"line": 3, "instruction": "RUN", "arguments": "apk add bash=5.1.0-r0"},
        {"line": 4, "instruction": "RUN", "arguments": "apk add curl=7.78.0-r0 vim=8.2.3456-r0"},
    ]
    errors = pin_apk_add_versions.check(parsed_content)
    assert len(errors) == 0


def test_pin_apk_add_versions_allows_package_files(pin_apk_add_versions):
    parsed_content = [
        {"line": 5, "instruction": "RUN", "arguments": "apk add /path/to/package.apk"},
    ]
    errors = pin_apk_add_versions.check(parsed_content)
    assert len(errors) == 0


def test_pin_apk_add_versions_handles_multiline_commands(pin_apk_add_versions):
    parsed_content = [
        {"line": 6, "instruction": "RUN", "arguments": "apk add bash=5.1.0-r0 \\\n    curl vim"},
    ]
    errors = pin_apk_add_versions.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 6


def test_pin_apk_add_versions_detects_mixed_unpinned_and_pinned(pin_apk_add_versions):
    parsed_content = [
        {"line": 7, "instruction": "RUN", "arguments": "apk add bash=5.1.0-r0 vim"},
    ]
    errors = pin_apk_add_versions.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 7
    assert errors[0]["message"] == (
        "Pin versions in apk add. Instead of `apk add <package>` use "
        "`apk add <package>=<version>`."
    )
