
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
