import pytest
from jasapp.rules.base_rule import BaseRule


class STX0020(BaseRule):
    """
    Rule to ensure that `COPY` with more than two arguments requires
    the last argument to end with '/'.
    """

    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="CopyMultipleArgs",
            hadolint="DL3020",  # Corrected Hadolint rule number
            name="STX0020",
            description="COPY with more than 2 arguments requires the last argument to end with '/'",
            severity="error",
        )

    def check(self, instructions):
        errors = []
        for instr in instructions:
            if instr["instruction"] == "COPY":
                args = instr["arguments"]

                # Correctly handle options like --from=...
                arg_list = []
                parts = args.split()
                skip_next = False
                for i, part in enumerate(parts):
                    if skip_next:
                        skip_next = False
                        continue
                    if part.startswith("--"):
                        # If it's an option, skip the next part (its value)
                        skip_next = True
                        continue  # Skip options
                    arg_list.append(part)

                if len(arg_list) > 2 and not arg_list[-1].endswith("/"):
                    errors.append({
                        "line": instr["line"],
                        "message": "COPY with more than 2 arguments requires the last argument to end with '/'",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def copy_multiple_args():
    return STX0020()


def test_copy_multiple_args_detects_missing_slash(copy_multiple_args):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "src1 src2 dest"},
    ]
    errors = copy_multiple_args.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["message"] == "COPY with more than 2 arguments requires the last argument to end with '/'"
    assert errors[0]["line"] == 1


def test_copy_multiple_args_allows_trailing_slash(copy_multiple_args):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "src1 src2 dest/"},
    ]
    errors = copy_multiple_args.check(parsed_content)
    assert len(errors) == 0


def test_copy_multiple_args_allows_two_args(copy_multiple_args):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "src dest"},
    ]
    errors = copy_multiple_args.check(parsed_content)
    assert len(errors) == 0


def test_copy_multiple_args_ignores_other_instructions(copy_multiple_args):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
    ]
    errors = copy_multiple_args.check(parsed_content)
    assert len(errors) == 0


def test_copy_multiple_args_with_options(copy_multiple_args):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "--from=previous /test.txt /root/test.txt"},
    ]
    errors = copy_multiple_args.check(parsed_content)
    assert len(errors) == 0


def test_copy_multiple_args_with_quotes(copy_multiple_args):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "\"src 1\" 'src 2' dest"},
    ]
    errors = copy_multiple_args.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
