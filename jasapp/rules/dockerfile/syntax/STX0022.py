import pytest
from jasapp.rules.base_rule import BaseRule


class STX0022(BaseRule):
    """
    Rule to ensure `COPY --from` does not reference its own `FROM` alias.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="CopyFromCannotReferenceOwnFromAlias",
            hadolint="DL3023",
            name="STX0022",
            description="`COPY --from` cannot reference its own `FROM` alias.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `COPY --from` references its own `FROM` alias.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        last_from_alias = None
        errors = []

        for instr in instructions:
            if instr["instruction"] == "FROM":
                arguments = instr["arguments"].split()
                if len(arguments) > 2 and arguments[-2].upper() == "AS":
                    last_from_alias = arguments[-1]
                else:
                    last_from_alias = None

            elif instr["instruction"] == "COPY" and "--from=" in instr["arguments"]:
                from_value = [
                    arg.split("=")[1] for arg in instr["arguments"].split() if arg.startswith("--from=")
                ][0]

                if from_value == last_from_alias:
                    errors.append({
                        "line": instr["line"],
                        "message": "`COPY --from` cannot reference its own `FROM` alias.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def copy_from_cannot_reference_own_from_alias():
    return STX0022()


def test_copy_from_cannot_reference_own_alias_detects_self_reference(copy_from_cannot_reference_own_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 2, "instruction": "COPY", "arguments": "--from=builder /app /app"},
    ]
    errors = copy_from_cannot_reference_own_from_alias.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert errors[0]["message"] == "`COPY --from` cannot reference its own `FROM` alias."


def test_copy_from_cannot_reference_own_alias_allows_different_alias(copy_from_cannot_reference_own_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest AS runtime"},
        {"line": 3, "instruction": "COPY", "arguments": "--from=builder /app /app"},
    ]
    errors = copy_from_cannot_reference_own_from_alias.check(parsed_content)
    assert len(errors) == 0


def test_copy_from_cannot_reference_own_alias_allows_stage_index(copy_from_cannot_reference_own_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest"},
        {"line": 2, "instruction": "COPY", "arguments": "--from=0 /app /app"},
    ]
    errors = copy_from_cannot_reference_own_from_alias.check(parsed_content)
    assert len(errors) == 0


def test_copy_from_cannot_reference_own_alias_handles_multiple_copies(copy_from_cannot_reference_own_from_alias):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest AS builder"},
        {"line": 2, "instruction": "COPY", "arguments": "--from=builder /app /app"},
        {"line": 3, "instruction": "FROM", "arguments": "ubuntu:latest AS runtime"},
        {"line": 4, "instruction": "COPY", "arguments": "--from=runtime /app /app"},
    ]
    errors = copy_from_cannot_reference_own_from_alias.check(parsed_content)
    assert len(errors) == 2  # Correction ici
    assert errors[0]["line"] == 2
    assert errors[0]["message"] == "`COPY --from` cannot reference its own `FROM` alias."
    assert errors[1]["line"] == 4
    assert errors[1]["message"] == "`COPY --from` cannot reference its own `FROM` alias."
