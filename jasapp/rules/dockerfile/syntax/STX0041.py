import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0041(BaseRule):
    """
    Rule to ensure that environment variables are not referred to within the same `ENV` statement where they are defined.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="NoSelfReferenceInEnv",
            hadolint="DL3044",
            name="STX0041",
            description="Do not refer to an environment variable within the same `ENV` statement where it is defined.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if environment variables are referred to within the same `ENV` statement where they are defined.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        defined_vars = set()

        for instr in instructions:
            if instr["instruction"] == "ENV":
                newly_defined_vars = []

                # First, check for self-references
                for pair in instr["arguments"].split():
                    if '=' in pair:
                        var_name, var_value = pair.split('=', 1)
                        if self.is_self_referenced(var_name, var_value, defined_vars):
                            message = f"Do not refer to an environment variable '{var_name}' within the same `ENV` statement where it is defined."
                            errors.append({
                                "line": instr["line"],
                                "message": message,
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })
                        newly_defined_vars.append(var_name)
                    else:
                        # Handle variables without explicit values
                        if self.is_self_referenced(pair, instr["arguments"], defined_vars):
                            errors.append({
                                "line": instr["line"],
                                "message": f"Do not refer to an environment variable '{pair}' within the same `ENV` statement where it is defined.",
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })
                        newly_defined_vars.append(pair)

                # Then, update defined_vars
                defined_vars.update(newly_defined_vars)

            elif instr["instruction"] == "ARG":
                # Extract variable name from ARG instruction (consider both forms: ARG var and ARG var=value)
                arg_parts = instr["arguments"].split("=", 1)
                if len(arg_parts) > 0:
                    defined_vars.add(arg_parts[0].strip())

        return errors

    def is_self_referenced(self, var_name, value_str, defined_vars):
        """
        Checks if an environment variable is self-referenced in the value part of an ENV instruction's arguments.

        Args:
            var_name (str): The name of the variable being defined.
            value_str (str): The value part of the variable assignment in the ENV instruction.
            defined_vars (set): The set of variables that have already been defined.

        Returns:
            bool: True if the variable is self-referenced, False otherwise.
        """
        # Regular expression to find variable references, both in ${var} and $var format
        pattern = rf"\$({var_name}|\{{{var_name}\}})"

        # Check if the variable is referenced in the value part
        matches = re.findall(pattern, value_str)
        for match in matches:
            if match == var_name or match == f"{{{var_name}}}":
                # Ensure the variable was not already defined
                if var_name not in defined_vars:
                    return True

        return False


@pytest.fixture
def no_self_reference_in_env():
    return STX0041()


def test_no_self_reference_in_env_detects_self_reference(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=hello MY_VAR=$MY_VAR"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "MY_VAR" in errors[0]["message"]


def test_no_self_reference_in_env_allows_no_self_reference(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=hello OTHER_VAR=world"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 0


def test_no_self_reference_in_env_allows_reference_to_previously_defined_variable(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=hello"},
        {"line": 2, "instruction": "ENV", "arguments": "OTHER_VAR=$MY_VAR"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 0


def test_no_self_reference_in_env_handles_curly_braces_notation(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "MY_VAR=hello MY_VAR=${MY_VAR}"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 1
    assert "MY_VAR" in errors[0]["message"]


def test_no_self_reference_in_env_ignores_other_instructions(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "RUN", "arguments": "echo $MY_VAR"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 0


def test_no_self_reference_in_env_detects_self_reference_mixed(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "A=$A B=b"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 1
    assert "A" in errors[0]["message"]


def test_no_self_reference_in_env_detects_self_reference_mixed_2(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "A=a B=$A"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 0


def test_no_self_reference_in_env_detects_self_reference_mixed_3(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "ENV", "arguments": "A=a B=$B"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 1
    assert "B" in errors[0]["message"]


def test_no_self_reference_in_env_detects_self_reference_mixed_4(no_self_reference_in_env):
    parsed_content = [
        {"line": 1, "instruction": "ARG", "arguments": "A"},
        {"line": 1, "instruction": "ENV", "arguments": "B=$A"},
    ]
    errors = no_self_reference_in_env.check(parsed_content)
    assert len(errors) == 0
