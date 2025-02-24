import re
import os
from typing import List, Dict, Tuple, Any
import pytest


class DockerfileParser:
    def __init__(self, dockerfile_path: str = None):
        self.dockerfile_path = dockerfile_path
        self.instructions: List[Dict[str, Any]] = []
        self.env_vars: Dict[str, str] = {}
        self.arg_vars: Dict[str, str] = {}

    def _parse_line(self, line: str) -> Tuple[str, str]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None, None

        parts = re.split(r"\s+", line, maxsplit=1)
        instruction = parts[0].upper()
        arguments = parts[1] if len(parts) > 1 else ""
        return instruction, arguments

    def _replace_variables(self, value: str) -> str:
        combined_vars = self.env_vars.copy()
        combined_vars.update(self.arg_vars)
        escaped_value = value.replace("\\$", "___ESCAPED_DOLLAR___")

        def replace(match):
            var_name = match.group(1) or match.group(2)
            return combined_vars.get(var_name, f"${{{var_name}}}")

        substituted_value = re.sub(
            r'\$(?:(\w+)|\{([\w\.]+)\})', replace, escaped_value
        )
        final_value = substituted_value.replace("___ESCAPED_DOLLAR___", "$")
        return final_value

    def _process_instruction(self, instruction: str, arguments: str, line_num: int):
        if instruction == "FROM":
            self.arg_vars = {}
            arguments = self._replace_variables(arguments)  # Replace *before* appending
            self.instructions.append(
                {"line": line_num, "instruction": instruction, "arguments": arguments}
            )
        elif instruction == "ENV":
            # Apply _replace_variables to the *entire* arguments string *before* parsing key/value
            arguments = self._replace_variables(arguments)  # <--- CORRECTION ICI
            parts = re.split(r"\s+", arguments)
            if "=" in arguments and len(parts) == 1:  # Single key=value
                key, value = arguments.split("=", 1)
                self.env_vars[key.strip()] = value.strip()  # No need to call _replace_variables again
            else:  # Multiple key=value
                for part in parts:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        self.env_vars[key.strip()] = value.strip()  # No need to call _replace_variables again
            self.instructions.append({"line": line_num, "instruction": instruction, "arguments": arguments})

        elif instruction == "ARG":
            parts = arguments.split("=", 1)
            var_name = parts[0].strip()
            default_value = parts[1].strip() if len(parts) > 1 else ""
            if default_value:
                default_value = self._replace_variables(default_value)

            if default_value or var_name in os.environ:
                self.arg_vars[var_name] = self._replace_variables(os.environ.get(var_name, default_value))

            self.instructions.append({"line": line_num, "instruction": instruction, "arguments": arguments})
        else:
            arguments = self._replace_variables(arguments)
            self.instructions.append(
                {"line": line_num, "instruction": instruction, "arguments": arguments}
            )

    def parse(self):
        self.instructions = []
        self.env_vars = {}
        self.arg_vars = {}
        try:
            with open(self.dockerfile_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    instruction, arguments = self._parse_line(line)
                    if instruction:
                        self._process_instruction(instruction, arguments, line_num)
        except FileNotFoundError:
            print(f"Error, file not found : {self.dockerfile_path}")
            return []
        return self.instructions

    def parse_from_string(self, content: str):
        """Parses the Dockerfile (from string)."""
        self.instructions = []
        self.env_vars = {}
        self.arg_vars = {}

        for line_num, line in enumerate(content.splitlines(), 1):
            instruction, arguments = self._parse_line(line)
            if instruction:
                self._process_instruction(instruction, arguments, line_num)
        return self.instructions


@pytest.fixture
def parser():
    return DockerfileParser()


def test_dockerfile_parser_variable_substitution(parser):
    content = """
FROM ubuntu:latest
ARG MY_VAR=default_value
ENV MY_ENV=$MY_VAR
RUN echo $MY_ENV
RUN echo ${MY_ENV}
RUN echo \$MY_ENV
"""
    instructions = parser.parse_from_string(content)
    assert instructions[1]["instruction"] == "ARG"
    assert instructions[1]["arguments"] == "MY_VAR=default_value"
    assert instructions[2]["instruction"] == "ENV"
    assert instructions[2]["arguments"] == "MY_ENV=default_value"  # NOW CORRECT
    assert instructions[3]["arguments"] == "echo default_value"
    assert instructions[4]["arguments"] == "echo default_value"
    assert instructions[5]["arguments"] == "echo $MY_ENV"


def test_dockerfile_parser_arg_override_env(parser):
    content = """
FROM ubuntu:latest
ENV MY_VAR=env_value
ARG MY_VAR=arg_value
RUN echo $MY_VAR
"""
    instructions = parser.parse_from_string(content)
    assert instructions[1]["instruction"] == "ENV"
    assert instructions[1]["arguments"] == "MY_VAR=env_value"
    assert instructions[2]["instruction"] == "ARG"
    assert instructions[2]["arguments"] == "MY_VAR=arg_value"
    assert instructions[3]["instruction"] == "RUN"
    assert instructions[3]["arguments"] == "echo arg_value"


def test_dockerfile_parser_arg_from_environment(parser):
    os.environ["MY_ARG"] = "env_arg_value"
    content = """
FROM ubuntu:latest
ARG MY_ARG
RUN echo $MY_ARG
"""
    instructions = parser.parse_from_string(content)
    del os.environ["MY_ARG"]
    assert instructions[1]["instruction"] == "ARG"
    assert instructions[1]["arguments"] == "MY_ARG"
    assert instructions[2]["instruction"] == "RUN"
    assert instructions[2]["arguments"] == "echo env_arg_value"


def test_dockerfile_parser_no_substitution_if_undefined(parser):
    content = """
FROM ubuntu:latest
RUN echo $UNDEFINED_VAR
"""
    instructions = parser.parse_from_string(content)
    assert instructions[1]["instruction"] == "RUN"
    assert instructions[1]["arguments"] == "echo ${UNDEFINED_VAR}"
