
import re


class DockerfileParser:
    """
    Parses a Dockerfile and extracts its instructions and arguments.
    """

    def __init__(self, file_path):
        """
        Initialize the parser with the path to the Dockerfile.

        Args:
            file_path (str): Path to the Dockerfile.
        """
        self.file_path = file_path

    def parse(self):
        """
        Parses the Dockerfile and returns a list of instructions.

        Returns:
            list: A list of dictionaries, each containing the line number,
                  instruction, and arguments.
        Raises:
            FileNotFoundError: If the specified file does not exist.
            Exception: For other unexpected parsing errors.
        """
        instructions = []
        try:
            with open(self.file_path, "r") as file:
                for line_number, line in enumerate(file, start=1):
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith("#"):
                        match = re.match(r"^(\w+)\s+(.*)$", stripped_line)
                        if match:
                            instructions.append({
                                "line": line_number,
                                "instruction": match.group(1).upper(),
                                "arguments": match.group(2).strip(),
                            })
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {self.file_path}")
        except Exception as e:
            raise Exception(f"An error occurred while parsing the file: {e}")
        return instructions

    def parse_from_string(self, content):
        """
        Parses a Dockerfile from a string and returns a list of instructions.

        Args:
            content (str): The content of the Dockerfile as a string.

        Returns:
            list: A list of dictionaries, each representing a parsed instruction.
        """
        self.instructions = []
        lines = content.splitlines()
        for line_number, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue  # Ignore empty lines and comments

            parts = line.split(maxsplit=1)
            instruction = parts[0].upper()
            arguments = parts[1] if len(parts) > 1 else ""

            # Join continued lines
            while arguments.endswith("\\"):
                line_number += 1
                try:
                    next_line = lines[line_number - 1].strip()
                    arguments = arguments[:-1] + " " + next_line  # Replace \ with a space
                except IndexError:
                    break

            self.instructions.append({
                "instruction": instruction,
                "arguments": arguments,
                "line": line_number,
            })

        return self.instructions
