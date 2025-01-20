import pytest
from jasapp.rules.base_rule import BaseRule


class STX0021(BaseRule):
    """
    Rule to ensure `COPY --from` references a previously defined `FROM` alias.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="CopyFromReferencesFromAlias",
            hadolint="DL3022",
            name="STX0021",
            description="`COPY --from` should reference a previously defined `FROM` alias.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `COPY --from` references a previously defined `FROM` alias.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        from_aliases = set()
        unnamed_from_count = 0
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM":
                arguments = instr["arguments"].split()
                if len(arguments) > 2 and arguments[-2].upper() == "AS":
                    alias = arguments[-1]
                    from_aliases.add(alias)
                else:
                    unnamed_from_count += 1

            elif instr["instruction"] == "COPY" and "--from=" in instr["arguments"]:
                from_value = [
                    arg.split("=")[1] for arg in instr["arguments"].split() if arg.startswith("--from=")
                ][0]

                # Check if `--from` references a valid alias or unnamed stage index
                if not (
                    from_value in from_aliases
                    or (from_value.isdigit() and int(from_value) < unnamed_from_count)
                ):
                    errors.append({
                        "line": instr["line"],
                        "message": "`COPY --from` should reference a previously defined `FROM` alias.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def copy_from_references_from_alias():
    return STX0021()


def test_copy_from_references_alias_detects_invalid_reference(copy_from_references_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 3, "instruction": "COPY", "arguments": "--from=invalid_alias /app /app"},
    ]
    errors = copy_from_references_from_alias.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 3
    assert errors[0]["message"] == "`COPY --from` should reference a previously defined `FROM` alias."


def test_copy_from_references_alias_allows_valid_alias(copy_from_references_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 2, "instruction": "COPY", "arguments": "--from=builder /app /app"},
    ]
    errors = copy_from_references_from_alias.check(parsed_content)
    assert len(errors) == 0


def test_copy_from_references_alias_allows_stage_index(copy_from_references_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 3, "instruction": "COPY", "arguments": "--from=0 /app /app"},
    ]
    errors = copy_from_references_from_alias.check(parsed_content)
    assert len(errors) == 0


def test_copy_from_references_alias_detects_invalid_stage_index(copy_from_references_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 2, "instruction": "COPY", "arguments": "--from=2 /app /app"},
    ]
    errors = copy_from_references_from_alias.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert errors[0]["message"] == "`COPY --from` should reference a previously defined `FROM` alias."


def test_copy_from_references_alias_allows_multiple_aliases(copy_from_references_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest AS runtime"},
        {"line": 3, "instruction": "COPY", "arguments": "--from=builder /app /app"},
        {"line": 4, "instruction": "COPY", "arguments": "--from=runtime /app /app"},
    ]
    errors = copy_from_references_from_alias.check(parsed_content)
    assert len(errors) == 0
