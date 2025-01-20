import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0035(BaseRule):
    """
    Rule to ensure `zypper install` or `zypper in` in RUN instructions specifies package versions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="SpecifyVersionWithZypperInstall",
            hadolint="DL3037",
            name="STX0035",
            description="Specify version with `zypper install -y <package>-<version>`.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `zypper install` or `zypper in` in RUN instructions specifies package versions.

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
                    errors.extend(self.check_zypper_install(instr["line"], command))

        return errors

    def split_commands(self, command_string):
        """
        Splits a command string into multiple commands based on && and ; delimiters.

        Args:
            command_string (str): The command string to split.

        Returns:
            list: A list of individual commands.
        """
        commands = re.split(r"[;&]", command_string)
        return [command.strip() for command in commands if command.strip()]

    def check_zypper_install(self, line, command_string):
        """
        Checks a single command for `zypper install` with version specification.

        Args:
            line (int): The line number of the instruction.
            command_string (str): The command string to check.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        packages = []
        modules = []

        if "zypper" in command_string and ("install" in command_string or "in" in command_string):
            parts = command_string.split()

            current_part = []

            for part in parts:
                if part == "zypper" and ("install" in current_part or "in" in current_part):
                    if (
                        "-y" not in current_part
                        and "--assumeyes" not in current_part
                        and "--no-confirm" not in current_part
                        and "-n" not in current_part
                    ):
                        errors.append({
                            "line": line,
                            "message": "Non-interactive switch missing from `zypper` command: `zypper --non-interactive install <package>`",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })

                    if any(word.startswith("module") for word in current_part):
                        for i in range(len(current_part)):
                            word = current_part[i]
                            if word in ["install", "in", "zypper", "module", "-y", "--assumeyes", "--no-confirm", "-n"] or word.startswith("-"):
                                continue

                            if not self.is_module_version_fixed(word):
                                modules.append(word)
                    else:
                        for i in range(len(current_part)):
                            word = current_part[i]
                            if word in ["install", "in", "zypper", "-y", "--assumeyes", "--no-confirm", "-n"] or word.startswith("-"):
                                continue

                            if not self.is_package_version_fixed(word):
                                packages.append(word)
                    current_part = []

                current_part.append(part)

            # Check the last part if it hasn't been processed yet
            if current_part:
                if "zypper" in current_part and ("install" in current_part or "in" in current_part):
                    if (
                        "-y" not in current_part
                        and "--assumeyes" not in current_part
                        and "--no-confirm" not in current_part
                        and "-n" not in current_part
                    ):
                        errors.append({
                            "line": line,
                            "message": "Non-interactive switch missing from `zypper` command: `zypper --non-interactive install <package>`",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })

                    if any(word.startswith("module") for word in current_part):
                        for i in range(len(current_part)):
                            word = current_part[i]
                            if word in ["install", "in", "zypper", "module", "-y", "--assumeyes", "--no-confirm", "-n"] or word.startswith("-"):
                                continue

                            if not self.is_module_version_fixed(word):
                                modules.append(word)
                    else:
                        for i in range(len(current_part)):
                            word = current_part[i]

                            if word in ["install", "in", "zypper", "-y", "--assumeyes", "--no-confirm", "-n"] or word.startswith("-"):
                                continue

                            if not self.is_package_version_fixed(word):
                                packages.append(word)

        for package in packages:
            errors.append({
                "line": line,
                "message": f"Specify version with `zypper install -y {package}=<version>`.",
                "severity": self.severity,
                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
            })

        for module in modules:
            errors.append({
                "line": line,
                "message": f"Specify version with `zypper module install -y {module}:<version>`.",
                "severity": self.severity,
                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
            })

        return errors

    def is_package_version_fixed(self, package_name):
        """
        Checks if a package name has a version specified (e.g., package-version or package.rpm).

        Args:
            package_name (str): The package name to check.

        Returns:
            bool: True if the package has a version specified, False otherwise.
        """
        return "-" in package_name or package_name.endswith(".rpm")

    def is_module_version_fixed(self, module_name):
        """
        Checks if a module name has a version specified (e.g., module:version).

        Args:
            module_name (str): The module name to check.

        Returns:
            bool: True if the module has a version specified, False otherwise.
        """
        return ":" in module_name


@pytest.fixture
def specify_version_with_zypper_install():
    return STX0035()


def test_specify_version_detects_unversioned_package(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Specify version with `zypper install -y httpd=<version>`" in errors[0]["message"]


def test_specify_version_allows_versioned_package(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd-2.4.6"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 0


def test_specify_version_allows_rpm_package(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y local-package.rpm"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 0


def test_specify_version_detects_unversioned_module(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper module install -y nodejs"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Specify version with `zypper module install -y nodejs:<version>`" in errors[0]["message"]


def test_specify_version_allows_versioned_module(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper module install -y nodejs:14"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 0


def test_specify_version_ignores_other_commands(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper update"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 0


def test_specify_version_handles_complex_commands(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd-2.4.6 && zypper install -y mariadb"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 1
    assert "mariadb" in errors[0]["message"]


def test_specify_version_handles_complex_commands_with_semicolon(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y httpd; zypper install -y mariadb"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 2
    assert "httpd" in errors[0]["message"]
    assert "mariadb" in errors[1]["message"]


def test_specify_version_handles_zypper_options(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper install -y --no-confirm httpd"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 1
    assert "httpd" in errors[0]["message"]


def test_specify_version_handles_zypper_short_options(specify_version_with_zypper_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "zypper in -n httpd"},
    ]
    errors = specify_version_with_zypper_install.check(parsed_content)
    assert len(errors) == 1
    assert "httpd" in errors[0]["message"]
