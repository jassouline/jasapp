import pytest
from jasapp.rules.base_rule import BaseRule


class STX0016(BaseRule):
    """
    Rule to ensure versions are pinned when using npm install.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="PinNpmVersions",
            hadolint="DL3016",
            name="STX0016",
            description=(
                "Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`."
            ),
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `npm install` commands pin the versions of installed packages.

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
                    if self.is_npm_install(command) and not self.is_version_pinned(command):
                        errors.append({
                            "line": instr["line"],
                            "message": (
                                "Pin versions in npm. Instead of `npm install <package>` use "
                                "`npm install <package>@<version>`."
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
    def is_npm_install(command):
        """
        Check if a command is an `npm install` command.

        Args:
            command (str): The command to check.

        Returns:
            bool: True if the command is an `npm install` command, False otherwise.
        """
        return command.startswith("npm install")

    @staticmethod
    def is_version_pinned(command):
        """
        Check if a `npm install` command pins versions for all packages.

        Args:
            command (str): The `npm install` command to check.

        Returns:
            bool: True if all packages in the command are version-pinned, False otherwise.
        """
        packages = command.replace("npm install", "").split()
        for package in packages:
            if not (
                STX0016.has_version_symbol(package)
                or STX0016.is_versioned_git(package)
                or STX0016.is_local_tarball(package)
                or STX0016.is_local_path(package)
            ):
                return False
        return True

    @staticmethod
    def has_version_symbol(package):
        return "@" in package and not package.startswith("@")

    @staticmethod
    def is_versioned_git(package):
        return "#" in package

    @staticmethod
    def is_local_tarball(package):
        return any(package.endswith(ext) for ext in [".tar", ".tar.gz", ".tgz"])

    @staticmethod
    def is_local_path(package):
        return any(package.startswith(prefix) for prefix in ["/", "./", "../", "~/"])


@pytest.fixture
def pin_npm_install_versions():
    return STX0016()


def test_pin_npm_install_versions_detects_unpinned_packages(pin_npm_install_versions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "npm install express"},
        {"line": 2, "instruction": "RUN", "arguments": "npm install react vue"},
    ]
    errors = pin_npm_install_versions.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert errors[1]["line"] == 2


def test_pin_npm_install_versions_allows_pinned_packages(pin_npm_install_versions):
    parsed_content = [
        {"line": 3, "instruction": "RUN", "arguments": "npm install express@4.17.1"},
        {"line": 4, "instruction": "RUN", "arguments": "npm install react@16 vue@3"},
    ]
    errors = pin_npm_install_versions.check(parsed_content)
    assert len(errors) == 0


def test_pin_npm_install_versions_allows_git_and_local_packages(pin_npm_install_versions):
    parsed_content = [
        {"line": 5, "instruction": "RUN", "arguments": "npm install git+https://github.com/user/repo#commit"},
        {"line": 6, "instruction": "RUN", "arguments": "npm install ./local-package"},
        {"line": 7, "instruction": "RUN", "arguments": "npm install ~/my-package.tgz"},
    ]
    errors = pin_npm_install_versions.check(parsed_content)
    assert len(errors) == 0


def test_pin_npm_install_versions_handles_multiline_commands(pin_npm_install_versions):
    parsed_content = [
        {"line": 8, "instruction": "RUN", "arguments": "npm install express@4.17.1 \\\n    react@16"},
    ]
    errors = pin_npm_install_versions.check(parsed_content)
    assert len(errors) == 0


def test_pin_npm_install_versions_detects_mixed_unpinned_and_pinned(pin_npm_install_versions):
    parsed_content = [
        {"line": 9, "instruction": "RUN", "arguments": "npm install express@4.17.1 react"},
    ]
    errors = pin_npm_install_versions.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 9
    assert errors[0]["message"] == (
        "Pin versions in npm. Instead of `npm install <package>` use "
        "`npm install <package>@<version>`."
    )
