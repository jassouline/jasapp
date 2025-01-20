import pytest
from jasapp.rules.base_rule import BaseRule


class STX0020(BaseRule):
    """
    Rule to ensure COPY with more than 2 arguments has the last argument ending with a '/'.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="EnsureCopyEndsWithSlash",
            hadolint="DL3021",
            name="STX0020",
            description="COPY with more than 2 arguments requires the last argument to end with '/'.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `COPY` with more than 2 arguments ends with a '/'.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "COPY":
                args = instr["arguments"].split()
                if len(args) > 2 and not args[-1].endswith("/"):
                    errors.append({
                        "line": instr["line"],
                        "message": "COPY with more than 2 arguments requires the last argument to end with '/'.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
        return errors


@pytest.fixture
def ensure_copy_ends_with_slash():
    return STX0020()


def test_ensure_copy_ends_with_slash_detects_missing_slash(ensure_copy_ends_with_slash):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "file1.txt file2.txt /app"},
        {"line": 2, "instruction": "COPY", "arguments": "file1.txt file2.txt /path/to/destination"},
    ]
    errors = ensure_copy_ends_with_slash.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["message"] == "COPY with more than 2 arguments requires the last argument to end with '/'."
    assert errors[0]["line"] == 1
    assert errors[1]["line"] == 2


def test_ensure_copy_ends_with_slash_allows_correct_usage(ensure_copy_ends_with_slash):
    parsed_content = [
        {"line": 3, "instruction": "COPY", "arguments": "file1.txt file2.txt /app/"},
        {"line": 4, "instruction": "COPY", "arguments": "file1.txt /app/"},
    ]
    errors = ensure_copy_ends_with_slash.check(parsed_content)
    assert len(errors) == 0


def test_ensure_copy_ends_with_slash_ignores_single_argument(ensure_copy_ends_with_slash):
    parsed_content = [
        {"line": 5, "instruction": "COPY", "arguments": "file1.txt /app"},
    ]
    errors = ensure_copy_ends_with_slash.check(parsed_content)
    assert len(errors) == 0
