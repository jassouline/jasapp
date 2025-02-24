import re
from typing import List, Dict, Tuple, Any

class DockerfileParser:
    def __init__(self, dockerfile_path: str = None):
        self.dockerfile_path = dockerfile_path
        self.instructions = []
        # Dictionnaire pour stocker les variables d'environnement et ARG
        self.env_vars: Dict[str, str] = {}
        self.arg_vars: Dict[str, str] = {}

    def _parse_line(self, line: str) -> Tuple[str, str]:
        """Parses a single line of a Dockerfile."""
        line = line.strip()
        if not line or line.startswith("#"):  # Ignore comments and empty lines
            return None, None

        parts = re.split(r"\s+", line, maxsplit=1)
        instruction = parts[0].upper()
        arguments = parts[1] if len(parts) > 1 else ""
        return instruction, arguments

    def _replace_variables(self, value: str) -> str:
        """
        Replaces environment variables and ARG variables in a string with their values.
        Handles escaping correctly.
        """
        # Prioritize ARG variables over ENV variables
        combined_vars = self.env_vars.copy()
        combined_vars.update(self.arg_vars)  # ARG values override ENV values

        # First, handle escaped dollar signs (e.g., \$VAR)
        escaped_value = value.replace("\\$", "___ESCAPED_DOLLAR___")

        # Function to substitute variables in the string
        def replace(match):
            var_name = match.group(1) or match.group(2)  # Get either $VAR or ${VAR}
            return combined_vars.get(var_name, f"${{{var_name}}}")  # Keep ${VAR} if not found


        # Regex to find variables (both $VAR and ${VAR} forms)
        substituted_value = re.sub(r'\$(?:(\w+)|\{([\w\.]+)\})', replace, escaped_value)

        # Restore escaped dollar signs
        final_value = substituted_value.replace("___ESCAPED_DOLLAR___", "$")
        return final_value

    def _process_instruction(self, instruction: str, arguments: str, line_num: int):
        """Processes a single Dockerfile instruction."""

        if instruction == "FROM":
            # Reset ARG vars for each stage (FROM resets ARG)
            self.arg_vars = {}
            arguments = self._replace_variables(arguments) # Important de remplacer les variables AVANT d'ajouter l'instruction
            self.instructions.append({"line": line_num, "instruction": instruction, "arguments": arguments})

        elif instruction == "ENV":
             # ENV can have multiple "key=value" pairs, or a single "key=value"
            parts = re.split(r"\s+", arguments)
            if '=' in arguments and len(parts) == 1: #Single key=value
                key, value = arguments.split("=", 1)
                key = key.strip()
                value = value.strip()
                self.env_vars[key] = self._replace_variables(value)  # replace variables *before* storing
            else: #Multiple key value
                for part in parts:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        self.env_vars[key.strip()] = self._replace_variables(value.strip())


        elif instruction == "ARG":
            # ARG can define a default value (ARG VAR=default) or not (ARG VAR)
            parts = arguments.split("=", 1)
            var_name = parts[0].strip()
            default_value = parts[1].strip() if len(parts) > 1 else ""
             # If the ARG variable has a default value, or if it's already defined in the environment, store it
            if default_value or var_name in os.environ:
                self.arg_vars[var_name] = self._replace_variables(default_value or os.environ[var_name])


        else:
            # For other instructions, replace variables in the arguments *before* storing
            arguments = self._replace_variables(arguments)
            self.instructions.append({"line": line_num, "instruction": instruction, "arguments": arguments})

    def parse(self) -> List[Dict[str, Any]]:
        """Parses the Dockerfile (from file)."""
        self.instructions = []
        self.env_vars = {}  # Reset ENV and ARG vars
        self.arg_vars = {}
        if not self.dockerfile_path: #Important
            return []
        try:
            with open(self.dockerfile_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    instruction, arguments = self._parse_line(line)
                    if instruction:
                        self._process_instruction(instruction, arguments, line_num)
        except FileNotFoundError:
            print(f"Error: Dockerfile not found at {self.dockerfile_path}")
            return []  # Return empty list if file not found

        return self.instructions

    def parse_from_string(self, content: str) -> List[Dict[str, Any]]:
        """Parses the Dockerfile (from string)."""
        self.instructions = []
        self.env_vars = {}  # Reset ENV and ARG vars
        self.arg_vars = {}

        for line_num, line in enumerate(content.splitlines(), 1):
            instruction, arguments = self._parse_line(line)
            if instruction:
                self._process_instruction(instruction, arguments, line_num)
        return self.instructions