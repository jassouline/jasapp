import pytest
from jasapp.rules.base_rule import BaseRule


class STX0024(BaseRule):
    """
    Rule to ensure CMD and ENTRYPOINT instructions use JSON array notation for arguments.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseJsonNotationForCmdAndEntrypointArgs",
            hadolint="DL3025",
            name="STX0024",
            description="Use arguments JSON notation for CMD and ENTRYPOINT arguments.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if CMD and ENTRYPOINT instructions use JSON array notation.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] in ("CMD", "ENTRYPOINT"):
                if not instr["arguments"].startswith("[") or not instr["arguments"].endswith("]"):
                    errors.append({
                        "line": instr["line"],
                        "message": "Use arguments JSON notation for CMD and ENTRYPOINT arguments.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def use_json_notation_for_cmd_and_entrypoint_args():
    return STX0024()


def test_use_json_notation_detects_string_notation_in_cmd(use_json_notation_for_cmd_and_entrypoint_args):
    parsed_content = [
        {"line": 1, "instruction": "CMD", "arguments": "echo hello"},
    ]
    errors = use_json_notation_for_cmd_and_entrypoint_args.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert errors[0]["message"] == "Use arguments JSON notation for CMD and ENTRYPOINT arguments."


def test_use_json_notation_detects_string_notation_in_entrypoint(use_json_notation_for_cmd_and_entrypoint_args):
    parsed_content = [
        {"line": 1, "instruction": "ENTRYPOINT", "arguments": "top -b"},
    ]
    errors = use_json_notation_for_cmd_and_entrypoint_args.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert errors[0]["message"] == "Use arguments JSON notation for CMD and ENTRYPOINT arguments."


def test_use_json_notation_allows_json_notation_in_cmd(use_json_notation_for_cmd_and_entrypoint_args):
    parsed_content = [
        {"line": 1, "instruction": "CMD", "arguments": '["echo", "hello"]'},
    ]
    errors = use_json_notation_for_cmd_and_entrypoint_args.check(parsed_content)
    assert len(errors) == 0


def test_use_json_notation_allows_json_notation_in_entrypoint(use_json_notation_for_cmd_and_entrypoint_args):
    parsed_content = [
        {"line": 1, "instruction": "ENTRYPOINT", "arguments": '["top", "-b"]'},
    ]
    errors = use_json_notation_for_cmd_and_entrypoint_args.check(parsed_content)
    assert len(errors) == 0
