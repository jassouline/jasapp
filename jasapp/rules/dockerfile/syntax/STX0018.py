import pytest
from jasapp.rules.base_rule import BaseRule


class STX0018(BaseRule):
    """
    Rule to ensure the `--no-cache` switch is used with `apk add` to avoid unnecessary updates and caching.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseNoCacheWithApk",
            hadolint="DL3019",
            name="STX0018",
            description=(
                "Use the `--no-cache` switch to avoid the need to use `--update` and remove `/var/cache/apk/*` when done installing packages."
            ),
            severity="info",
        )

    def check(self, instructions):
        """
        Checks if the `--no-cache` option is used with `apk add` commands.

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
                    if self.is_apk_add(command) and not self.has_no_cache_flag(command):
                        errors.append({
                            "line": instr["line"],
                            "message": (
                                "Use the `--no-cache` switch to avoid the need to use `--update` "
                                "and remove `/var/cache/apk/*` when done installing packages."
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
        result = command.startswith("apk add")
        return result

    @staticmethod
    def has_no_cache_flag(command):
        """
        Check if the `apk add` command applies `--no-cache` correctly to all packages.

        Args:
            command (str): The `apk add` command to check.

        Returns:
            bool: True if `--no-cache` is applied correctly, False otherwise.
        """
        tokens = command.split()

        if "--no-cache" not in tokens:
            return False

        # Split tokens into before and after `--no-cache`
        no_cache_index = tokens.index("--no-cache")
        before_no_cache = tokens[:no_cache_index]
        after_no_cache = tokens[no_cache_index + 1:]

        # Ensure no packages appear before `--no-cache`
        for token in before_no_cache:
            if not token.startswith("--") and token not in {"apk", "add"}:
                return False

        # Ensure all tokens after `--no-cache` are valid packages
        for token in after_no_cache:
            if token.startswith("--"):
                return False

        return True


@pytest.fixture
def use_no_cache_with_apk():
    return STX0018()


def test_use_no_cache_with_apk_detects_missing_no_cache(use_no_cache_with_apk):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apk add bash"},
        {"line": 2, "instruction": "RUN", "arguments": "apk add curl vim"},
    ]
    errors = use_no_cache_with_apk.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert errors[1]["line"] == 2


def test_use_no_cache_with_apk_allows_with_no_cache(use_no_cache_with_apk):
    parsed_content = [
        {"line": 3, "instruction": "RUN", "arguments": "apk add --no-cache bash"},
        {"line": 4, "instruction": "RUN", "arguments": "apk add --no-cache curl vim"},
    ]
    errors = use_no_cache_with_apk.check(parsed_content)
    assert len(errors) == 0


def test_use_no_cache_with_apk_handles_multiline_commands(use_no_cache_with_apk):
    parsed_content = [
        {"line": 5, "instruction": "RUN", "arguments": "apk add bash \\\n    curl vim"},
    ]
    errors = use_no_cache_with_apk.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 5


def test_use_no_cache_with_apk_detects_mixed_flags(use_no_cache_with_apk):
    parsed_content = [
        {"line": 6, "instruction": "RUN", "arguments": "apk add bash --no-cache \\\n    curl"},
    ]
    errors = use_no_cache_with_apk.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 6
    assert errors[0]["message"] == (
        "Use the `--no-cache` switch to avoid the need to use `--update` "
        "and remove `/var/cache/apk/*` when done installing packages."
    )


def test_use_no_cache_with_apk_detects_flags_after_no_cache(use_no_cache_with_apk):
    parsed_content = [
        {"line": 5, "instruction": "RUN", "arguments": "apk add --no-cache bash --some-flag"},
    ]
    errors = use_no_cache_with_apk.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 5
