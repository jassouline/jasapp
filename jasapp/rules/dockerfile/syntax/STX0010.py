import pytest
from jasapp.rules.base_rule import BaseRule


class STX0010(BaseRule):
    """
    Rule to ensure that archives are extracted into an image using `ADD` instead of `COPY` followed by extraction commands.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseAddForArchives",
            hadolint="DL3010",
            name="STX0010",
            description="Use `ADD` for extracting archives into an image.",
            severity="info",
        )

    @staticmethod
    def is_archive(file_name):
        """
        Check if a file is an archive based on its extension.

        Args:
            file_name (str): The name of the file.

        Returns:
            bool: True if the file is an archive, False otherwise.
        """
        archive_extensions = {".tar", ".gz", ".bz2", ".xz", ".zip", ".7z", ".tgz"}
        return any(file_name.endswith(ext) for ext in archive_extensions)

    def check(self, instructions):
        """
        Checks if archives are extracted using `ADD` instead of `COPY` and `RUN` commands.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        copied_archives = {}

        for instr in instructions:
            if instr["instruction"] == "COPY":
                args = instr["arguments"].split()
                if len(args) < 2:
                    continue  # Skip invalid COPY instructions
                sources = args[:-1]
                for source in sources:
                    if self.is_archive(source):
                        copied_archives[source] = instr["line"]

            elif instr["instruction"] == "RUN":
                commands = instr["arguments"].split("&&")
                for command in commands:
                    command = command.strip()
                    for archive, line in copied_archives.items():
                        message = f"Archive '{archive}' is copied using `COPY` and then extracted in `RUN`."
                        more_comments = "Use `ADD` to extract the archive directly."
                        if self.is_archive_extracted(command, archive):
                            errors.append({
                                "line": line,
                                "message": message + " " + more_comments,
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })

        return errors

    @staticmethod
    def is_archive_extracted(command, archive):
        """
        Check if a command extracts a specific archive.

        Args:
            command (str): The command to check.
            archive (str): The archive name to check.

        Returns:
            bool: True if the command extracts the archive, False otherwise.
        """
        extract_commands = {"tar -x", "unzip", "gunzip", "bunzip2", "unxz", "zcat", "gzcat"}
        return any(cmd in command for cmd in extract_commands) and archive in command


@pytest.fixture
def use_add_for_archives():
    return STX0010()


def test_use_add_for_archives_detects_copy_followed_by_extraction(use_add_for_archives):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "archive.tar /app"},
        {"line": 2, "instruction": "RUN", "arguments": "cd /app && tar -xvf archive.tar"},
    ]
    errors = use_add_for_archives.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    message = "Archive 'archive.tar' is copied using `COPY` and then extracted in `RUN`. Use `ADD` to extract the archive directly."
    assert errors[0]["message"] == message


def test_use_add_for_archives_allows_add_directly(use_add_for_archives):
    parsed_content = [
        {"line": 1, "instruction": "ADD", "arguments": "archive.tar /app"},
    ]
    errors = use_add_for_archives.check(parsed_content)
    assert len(errors) == 0


def test_use_add_for_archives_allows_non_archive_files(use_add_for_archives):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "file.txt /app"},
        {"line": 2, "instruction": "RUN", "arguments": "echo 'Hello World'"},
    ]
    errors = use_add_for_archives.check(parsed_content)
    assert len(errors) == 0


def test_use_add_for_archives_detects_multiple_archives(use_add_for_archives):
    parsed_content = [
        {"line": 1, "instruction": "COPY", "arguments": "archive1.tar /app"},
        {"line": 2, "instruction": "COPY", "arguments": "archive2.zip /app"},
        {"line": 3, "instruction": "RUN", "arguments": "cd /app && tar -xvf archive1.tar && unzip archive2.zip"},
    ]
    errors = use_add_for_archives.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert errors[1]["line"] == 2
