import pytest
from jasapp.rules.base_rule import BaseRule


class STX0026(BaseRule):
    """
    Rule to ensure 'apt' is not used in RUN instructions. Use 'apt-get' or 'apt-cache' instead.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="DoNotUseAptInRunInstructions",
            hadolint="DL3027",
            name="STX0026",
            description="Do not use apt as it is meant to be an end-user tool, use apt-get or apt-cache instead.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if 'apt' is used in RUN instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "RUN":
                arguments = instr["arguments"]
                if "apt " in arguments:
                    errors.append({
                        "line": instr["line"],
                        "message": "Do not use apt as it is meant to be an end-user tool, use apt-get or apt-cache instead.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def do_not_use_apt_in_run_instructions():
    return STX0026()


def test_do_not_use_apt_detects_apt_in_run(do_not_use_apt_in_run_instructions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt update && apt install -y curl"},
    ]
    errors = do_not_use_apt_in_run_instructions.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert errors[0]["message"] == "Do not use apt as it is meant to be an end-user tool, use apt-get or apt-cache instead."


def test_do_not_use_apt_allows_apt_get_in_run(do_not_use_apt_in_run_instructions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-get update && apt-get install -y curl"},
    ]
    errors = do_not_use_apt_in_run_instructions.check(parsed_content)
    assert len(errors) == 0


def test_do_not_use_apt_allows_apt_cache_in_run(do_not_use_apt_in_run_instructions):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "apt-cache search curl"},
    ]
    errors = do_not_use_apt_in_run_instructions.check(parsed_content)
    assert len(errors) == 0


def test_do_not_use_apt_ignores_other_instructions(do_not_use_apt_in_run_instructions):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=apt"},
    ]
    errors = do_not_use_apt_in_run_instructions.check(parsed_content)
    assert len(errors) == 0
