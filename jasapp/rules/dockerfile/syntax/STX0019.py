import pytest
from jasapp.rules.base_rule import BaseRule


class STX0019(BaseRule):
    """
    Rule to ensure COPY is used instead of ADD for files and folders.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="UseCopyInsteadOfAdd",
            hadolint="DL3020",
            name="STX0019",
            description="Use COPY instead of ADD for files and folders.",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if ADD is used for files and folders instead of COPY.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "ADD":
                sources = instr["arguments"].split()[:-1]
                if not all(self.is_archive_or_url(src) for src in sources):
                    errors.append({
                        "line": instr["line"],
                        "message": "Use COPY instead of ADD for files and folders.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })
        return errors

    @staticmethod
    def is_archive_or_url(path):
        """
        Check if a path is an archive or a URL.

        Args:
            path (str): The path to check.

        Returns:
            bool: True if the path is an archive or URL, False otherwise.
        """
        return STX0019.is_archive(path) or STX0019.is_url(path)

    @staticmethod
    def is_archive(path):
        """
        Check if a path is an archive based on its extension.

        Args:
            path (str): The path to check.

        Returns:
            bool: True if the path is an archive, False otherwise.
        """
        archive_extensions = {".tar", ".gz", ".bz2", ".xz", ".zip", ".7z", ".tgz"}
        return any(path.endswith(ext) for ext in archive_extensions)

    @staticmethod
    def is_url(path):
        """
        Check if a path is a URL.

        Args:
            path (str): The path to check.

        Returns:
            bool: True if the path is a URL, False otherwise.
        """
        return path.startswith("http://") or path.startswith("https://")


@pytest.fixture
def use_copy_instead_of_add():
    return STX0019()


def test_use_copy_instead_of_add_detects_invalid_add(use_copy_instead_of_add):
    parsed_content = [
        {"line": 1, "instruction": "ADD", "arguments": "file.txt /app"},
        {"line": 2, "instruction": "ADD", "arguments": "folder /app"},
    ]
    errors = use_copy_instead_of_add.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["message"] == "Use COPY instead of ADD for files and folders."
    assert errors[0]["line"] == 1
    assert errors[1]["line"] == 2


def test_use_copy_instead_of_add_allows_valid_add(use_copy_instead_of_add):
    parsed_content = [
        {"line": 3, "instruction": "ADD", "arguments": "https://example.com/archive.tar.gz /app"},
        {"line": 4, "instruction": "ADD", "arguments": "file.tar.gz /app"},
    ]
    errors = use_copy_instead_of_add.check(parsed_content)
    assert len(errors) == 0


def test_use_copy_instead_of_add_ignores_copy(use_copy_instead_of_add):
    parsed_content = [
        {"line": 5, "instruction": "COPY", "arguments": "file.txt /app"},
        {"line": 6, "instruction": "COPY", "arguments": "folder /app"},
    ]
    errors = use_copy_instead_of_add.check(parsed_content)
    assert len(errors) == 0
