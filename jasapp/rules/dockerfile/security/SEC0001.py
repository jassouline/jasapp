import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0001(BaseRule):
    rule_type = "dockerfile"

    """
    Rule to ensure that the last USER instruction in each stage is not 'root'.
    """

    def __init__(self):
        super().__init__(
            friendly_name="AvoidRootAsLastUser",
            hadolint="DL3002",
            name="SEC0001",
            description="The last USER in each stage should not be root.",
            severity="warning",
        )

    @staticmethod
    def is_root_user(user):
        """
        Check if a user is root.

        Args:
            user (str): The user string to check.

        Returns:
            bool: True if the user is root, False otherwise.
        """
        return user in {"root", "0"} or user.startswith("root:") or user.startswith("0:")

    def check(self, instructions):
        """
        Check that the last USER instruction in each stage is not 'root'.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        last_user_line = None
        in_stage = False

        for instr in instructions:
            if instr["instruction"] == "FROM":
                # New stage detected
                if last_user_line is not None:
                    errors.append({
                        "line": last_user_line,
                        "message": "The last USER in the previous stage is 'root'. Avoid using root as the final user.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
                in_stage = True
                last_user_line = None

            elif instr["instruction"] == "USER" and in_stage:
                user = instr["arguments"].strip()
                if self.is_root_user(user):
                    last_user_line = instr["line"]
                else:
                    last_user_line = None  # Non-root user found, reset tracking

        # Check if the last stage ends with root
        if last_user_line is not None:
            errors.append({
                "line": last_user_line,
                "message": "The last USER in the stage is 'root'. Avoid using root as the final user.",
                "severity": self.severity,
                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
            })

        return errors


@pytest.fixture
def avoid_root_as_last_user():
    return SEC0001()


# Test for SEC0001
def test_avoid_root_as_last_user_detects_root(avoid_root_as_last_user):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:20.04"},
        {"line": 2, "instruction": "USER", "arguments": "root"},
    ]
    errors = avoid_root_as_last_user.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["message"] == "The last USER in the stage is 'root'. Avoid using root as the final user."
    assert errors[0]["line"] == 2


def test_avoid_root_as_last_user_detects_non_root(avoid_root_as_last_user):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:20.04"},
        {"line": 2, "instruction": "USER", "arguments": "appuser"},
    ]
    errors = avoid_root_as_last_user.check(parsed_content)
    assert len(errors) == 0


def test_avoid_root_as_last_user_multiple_stages(avoid_root_as_last_user):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:20.04"},
        {"line": 2, "instruction": "USER", "arguments": "root"},
        {"line": 3, "instruction": "FROM", "arguments": "alpine"},
        {"line": 4, "instruction": "USER", "arguments": "appuser"},
        {"line": 5, "instruction": "USER", "arguments": "root"},
    ]
    errors = avoid_root_as_last_user.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 2
    assert errors[0]["message"] == "The last USER in the previous stage is 'root'. Avoid using root as the final user."
    assert errors[1]["line"] == 5
    assert errors[1]["message"] == "The last USER in the stage is 'root'. Avoid using root as the final user."
