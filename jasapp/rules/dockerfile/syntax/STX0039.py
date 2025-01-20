import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0039(BaseRule):
    """
    Rule to ensure `pip install` uses `--no-cache-dir` to avoid caching packages in the image.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseNoCacheDirWithPipInstall",
            hadolint="DL3042",
            name="STX0039",
            description="Avoid using cache directory with pip. Use `pip install --no-cache-dir <package>`",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `pip install` uses `--no-cache-dir` in RUN instructions, unless there is an env variable to disable
        pip cache

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        env_vars = {}
        for instr in instructions:
            if instr["instruction"] == "ENV":
                for key, value in self.parse_env_instruction(instr["arguments"]):
                    env_vars[key] = value

            if instr["instruction"] == "RUN":
                commands = self.split_commands(instr["arguments"])
                for command in commands:
                    if self.is_pip_install_without_no_cache_dir(command, env_vars):
                        errors.append({
                            "line": instr["line"],
                            "message": "Avoid using cache directory with pip. "
                                       "Use `pip install --no-cache-dir <package>`",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })

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

    def is_pip_install_without_no_cache_dir(self, command_string, env_vars):
        """
        Checks if a command string is a `pip install` command without the `--no-cache-dir` flag.

        Args:
            command_string (str): The command string to check.

        Returns:
            bool: True if it's a `pip install` without `--no-cache-dir`, False otherwise.
        """

        if "pip" not in command_string or "install" not in command_string:
            return False

        words = re.split(r"\s+", command_string)

        if "pip" not in words:
            return False

        if "--no-cache-dir" in words:
            return False

        if "PIP_NO_CACHE_DIR" in env_vars:
            if env_vars["PIP_NO_CACHE_DIR"] in ["1", "true", "True", "TRUE", "on", "On", "ON", "yes", "Yes", "YES"]:
                return False

        if any(w in ["pipenv", "pipx"] for w in words):
            return False

        if any("python" in word and "-m" in words and any(w in ["pipenv", "pipx"] for w in words) for word in words):
            return False

        return True

    def parse_env_instruction(self, arguments):
        """
        Parses an ENV instruction's arguments and returns a list of key-value pairs.

        Args:
            arguments (str): The arguments of the ENV instruction.

        Returns:
            list: A list of tuples, each representing a key-value pair.
        """
        pairs = []

        # Remove any trailing comments from the arguments string
        arguments = arguments.split("#")[0].strip()

        # Handle multi-line ENV instructions
        while arguments.endswith("\\"):
            arguments = arguments[:-1].strip() + " "
            # Here you would normally read the next line from the Dockerfile, but since we're processing
            # individual instructions, we'll just append a placeholder
            arguments += "NEXT_LINE"  # Replace "NEXT_LINE" with actual next line content in a real scenario

        # Split the arguments into words
        words = arguments.split()

        i = 0
        while i < len(words):
            # Check if the word contains an equals sign, indicating a key-value pair
            if '=' in words[i]:
                key, value = words[i].split('=', 1)
                pairs.append((key, value))
                i += 1
            # If the word does not contain an equals sign, it's a key without a value in the same word
            elif i + 1 < len(words):
                key = words[i]
                value = words[i + 1]
                pairs.append((key, value))
                i += 2
            else:
                # If there's no value following the key, assign an empty string as the value
                key = words[i]
                pairs.append((key, ""))
                i += 1

        return pairs


@pytest.fixture
def use_no_cache_dir_with_pip_install():
    return STX0039()


def test_pip_install_no_cache_dir_detects_missing_flag(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pip install requests"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Avoid using cache directory with pip" in errors[0]["message"]


def test_pip_install_no_cache_dir_allows_flag(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pip install --no-cache-dir requests"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 0


def test_pip_install_no_cache_dir_allows_pipenv(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pipenv install requests"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 0


def test_pip_install_no_cache_dir_allows_pipx(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pipx install requests"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 0


def test_pip_install_no_cache_dir_handles_complex_commands(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pip install requests && pip install --no-cache-dir pandas"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 1
    assert "Avoid using cache directory with pip" in errors[0]["message"]


def test_pip_install_no_cache_dir_handles_complex_commands_with_semicolon(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "pip install requests; pip install --no-cache-dir pandas"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 1
    assert "Avoid using cache directory with pip" in errors[0]["message"]


def test_pip_install_no_cache_dir_ignores_other_instructions(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=value"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 0


def test_pip_install_no_cache_dir_with_env_setting(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "PIP_NO_CACHE_DIR=1"},
        {"line": 2, "instruction": "RUN", "arguments": "pip install requests"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 0


def test_pip_install_no_cache_dir_with_env_setting_multiline(use_no_cache_dir_with_pip_install):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "PIP_NO_CACHE_DIR=1 \\"},
        {"line": 2, "instruction": "", "arguments": "      MY_VAR=2"},
        {"line": 3, "instruction": "RUN", "arguments": "pip install requests"},
    ]
    errors = use_no_cache_dir_with_pip_install.check(parsed_content)
    assert len(errors) == 0
