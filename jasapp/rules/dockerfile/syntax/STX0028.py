import pytest
from jasapp.rules.base_rule import BaseRule


class STX0028(BaseRule):
    """
    Rule to ensure `--platform` flag is not used with `FROM` instruction,
    unless it's a variable like BUILDPLATFORM or TARGETPLATFORM.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="DoNotUsePlatformFlagWithFrom",
            hadolint="DL3029",
            name="STX0028",
            description="Do not use --platform flag with FROM, unless it's a variable like BUILDPLATFORM or TARGETPLATFORM",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `--platform` flag is used with `FROM` instruction.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM" and "--platform" in instr["arguments"]:
                # Check if it's a variable or a fixed value
                if not any(var in instr["arguments"] for var in ["BUILDPLATFORM", "TARGETPLATFORM"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "Do not use --platform flag with FROM, unless it's a variable like BUILDPLATFORM or TARGETPLATFORM",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def do_not_use_platform_flag_with_from():
    return STX0028()


def test_do_not_use_platform_flag_detects_platform_flag(do_not_use_platform_flag_with_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "--platform=linux/amd64 alpine:latest"},
    ]
    errors = do_not_use_platform_flag_with_from.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Do not use --platform flag with FROM" in errors[0]["message"]


def test_do_not_use_platform_flag_allows_platform_variable(do_not_use_platform_flag_with_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "--platform=$BUILDPLATFORM alpine:latest"},
    ]
    errors = do_not_use_platform_flag_with_from.check(parsed_content)
    assert len(errors) == 0


def test_do_not_use_platform_flag_allows_platform_variable_2(do_not_use_platform_flag_with_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "--platform=$TARGETPLATFORM alpine:latest"},
    ]
    errors = do_not_use_platform_flag_with_from.check(parsed_content)
    assert len(errors) == 0


def test_do_not_use_platform_flag_ignores_other_instructions(do_not_use_platform_flag_with_from):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = do_not_use_platform_flag_with_from.check(parsed_content)
    assert len(errors) == 0
