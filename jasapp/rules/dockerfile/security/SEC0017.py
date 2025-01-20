import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0017(BaseRule):
    """
    Rule to detect if the `NODE_TLS_REJECT_UNAUTHORIZED` environment variable is set to `0`,
    disabling TLS certificate validation for Node.js applications.

    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="NodeTLSRejectUnauthorizedDisabled",
            name="SEC0017",
            description="`NODE_TLS_REJECT_UNAUTHORIZED` environment variable is set to `0`, disabling TLS certificate validation.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if the `NODE_TLS_REJECT_UNAUTHORIZED` environment variable is set to `0` in `ENV` instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []

        for instr in instructions:
            if instr["instruction"] == "ENV":
                if self.is_node_tls_reject_unauthorized_disabled(instr["arguments"]):
                    errors.append({
                        "line": instr["line"],
                        "message": "`NODE_TLS_REJECT_UNAUTHORIZED` environment variable is set to `0`, "
                                   "disabling TLS certificate validation for Node.js applications.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_node_tls_reject_unauthorized_disabled(self, arguments):
        """
        Checks if the `NODE_TLS_REJECT_UNAUTHORIZED` environment variable is set to `0` in an `ENV` instruction's arguments.

        Args:
            arguments (str): The arguments of the `ENV` instruction.

        Returns:
            bool: True if `NODE_TLS_REJECT_UNAUTHORIZED` is set to `0`, False otherwise.
        """
        for pair in arguments.split():
            if "=" in pair:
                key, value = pair.split("=", 1)
                if key.strip() == "NODE_TLS_REJECT_UNAUTHORIZED" and value.strip().strip("'\"") == "0":
                    return True
        return False


@pytest.fixture
def node_tls_reject_unauthorized_disabled():
    return SEC0017()


def test_node_tls_reject_unauthorized_detects_disabled_verification(node_tls_reject_unauthorized_disabled):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "NODE_TLS_REJECT_UNAUTHORIZED=0"},
    ]
    errors = node_tls_reject_unauthorized_disabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`NODE_TLS_REJECT_UNAUTHORIZED` environment variable is set to `0`" in errors[0]["message"]


def test_node_tls_reject_unauthorized_allows_enabled_verification(node_tls_reject_unauthorized_disabled):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "NODE_TLS_REJECT_UNAUTHORIZED=1"},
    ]
    errors = node_tls_reject_unauthorized_disabled.check(parsed_content)
    assert len(errors) == 0


def test_node_tls_reject_unauthorized_ignores_other_instructions(node_tls_reject_unauthorized_disabled):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo hello"},
    ]
    errors = node_tls_reject_unauthorized_disabled.check(parsed_content)
    assert len(errors) == 0
