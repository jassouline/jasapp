import re
import pytest
from jasapp.rules.base_rule import BaseRule


class STX0042(BaseRule):
    """
    Rule to ensure `COPY` in Dockerfiles uses an absolute destination path when `WORKDIR` is not set.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="CopyWithoutWorkdir",
            hadolint="DL3045",
            name="STX0042",
            description="`COPY` to a relative destination without `WORKDIR` set.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if `COPY` instructions use a relative destination path when `WORKDIR` is not set.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        workdir_set = False
        for instr in instructions:
            if instr["instruction"] == "WORKDIR":
                workdir_set = True
            elif instr["instruction"] == "COPY":

                arguments = instr["arguments"].split()

                if instr["arguments"].startswith("--from"):
                    arguments = arguments[1:]
                    if "=" in arguments[0]:
                        arguments = arguments[1:]

                if len(arguments) >= 2:
                    dest = arguments[-1]
                    if not workdir_set and not self.is_absolute_path(dest):
                        errors.append({
                            "line": instr["line"],
                            "message": "`COPY` to a relative destination without `WORKDIR` set.",
                            "severity": self.severity,
                            "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                        })
            elif instr["instruction"] == "FROM":
                workdir_set = False

        return errors

    def is_absolute_path(self, path):
        """
        Checks if a path is absolute.

        Args:
            path (str): The path to check.

        Returns:
            bool: True if the path is absolute, False otherwise.
        """
        # Remove quotes if present
        path = path.strip("'\"")

        # Check for standard absolute paths
        if path.startswith("/"):
            return True

        # Check for Windows absolute paths (e.g., C:\path)
        if re.match(r"^[a-zA-Z]:\\", path):
            return True

        # Check for variable (e.g $VAR)
        if path.startswith("$"):
            return True

        return False


@pytest.fixture
def copy_without_workdir():
    return STX0042()


def test_copy_to_relative_path_without_workdir(copy_without_workdir):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "source dest"},
    ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`COPY` to a relative destination without `WORKDIR` set." in errors[0]["message"]


def test_copy_to_absolute_path_without_workdir(copy_without_workdir):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "source /dest"},
    ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 0


def test_copy_to_relative_path_with_workdir(copy_without_workdir):
    parsed_content = [
        {"line": 1, "instruction": "WORKDIR", "arguments": "/app"},
        {"line": 2, "instruction": "COPY", "arguments": "source dest"},
    ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 0


def test_copy_to_absolute_path_with_workdir(copy_without_workdir):
    parsed_content = [
        {"line": 1, "instruction": "WORKDIR", "arguments": "/app"},
        {"line": 2, "instruction": "COPY", "arguments": "source /dest"},
    ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 0


def test_copy_resets_workdir_after_from(copy_without_workdir):
    parsed_content = [
        {"line": 1, "instruction": "WORKDIR", "arguments": "/app"},
        {"line": 2, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 3, "instruction": "COPY", "arguments": "source dest"},
    ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 3
    assert "`COPY` to a relative destination without `WORKDIR` set." in errors[0]["message"]


def test_copy_with_from_argument(copy_without_workdir):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "--from=stage source dest"},
    ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "`COPY` to a relative destination without `WORKDIR` set." in errors[0]["message"]


def test_copy_with_from_argument_with_workdir(copy_without_workdir):
    parsed_content = [
        {"line": 1, "instruction": "WORKDIR", "arguments": "/app"},
        {"line": 2, "instruction": "COPY", "arguments": "--from=stage source dest"},
    ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 0


def test_copy_with_from_argument_absolute(copy_without_workdir):
    parsed_content = [
            {"line": 1, "instruction": "COPY", "arguments": "--from=stage source /dest"},
        ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 0


def test_copy_with_from_variable(copy_without_workdir):
    parsed_content = [
            {"line": 1, "instruction": "COPY", "arguments": "--from=stage source $dest"},
        ]
    errors = copy_without_workdir.check(parsed_content)
    assert len(errors) == 0
