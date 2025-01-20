import pytest
from jasapp.rules.base_rule import BaseRule


class STX0006(BaseRule):
    """
    Rule to ensure that the 'latest' tag is not used in FROM instructions.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="AvoidLatestTag",
            hadolint="DL3007",
            name="STX0006",
            description="Avoid using the 'latest' tag in FROM instructions. Pin the version explicitly to a release tag.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Check if FROM instructions use the 'latest' tag.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        for instr in instructions:
            if instr["instruction"] == "FROM":
                parts = instr["arguments"].split()
                image = parts[0]
                tag = image.split(":")[-1] if ":" in image else None

                # Skip images with digests
                if "@" in image:
                    continue

                # Check if the tag is 'latest'
                if tag == "latest":
                    errors.append({
                        "line": instr["line"],
                        "message": "Using 'latest' is prone to errors if the image updates. Pin the version explicitly to a release tag.",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def avoid_latest_tag():
    return STX0006()


def test_avoid_latest_tag_detects_latest_tag(avoid_latest_tag):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu:latest"},
        {"line": 2, "instruction": "FROM", "arguments": "alpine:latest"},
    ]
    errors = avoid_latest_tag.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["message"] == "Using 'latest' is prone to errors if the image updates. Pin the version explicitly to a release tag."
    assert errors[0]["line"] == 1
    assert errors[1]["message"] == "Using 'latest' is prone to errors if the image updates. Pin the version explicitly to a release tag."
    assert errors[1]["line"] == 2


def test_avoid_latest_tag_allows_pinned_versions(avoid_latest_tag):
    parsed_content = [
        {"line": 3, "instruction": "FROM", "arguments": "ubuntu:20.04"},
        {"line": 4, "instruction": "FROM", "arguments": "alpine:3.14"},
    ]
    errors = avoid_latest_tag.check(parsed_content)
    assert len(errors) == 0


def test_avoid_latest_tag_allows_digests(avoid_latest_tag):
    parsed_content = [
        {"line": 5, "instruction": "FROM", "arguments": "ubuntu@sha256:abcdef1234567890"},
    ]
    errors = avoid_latest_tag.check(parsed_content)
    assert len(errors) == 0


def test_avoid_latest_tag_detects_no_tag(avoid_latest_tag):
    parsed_content = [
        {"line": 6, "instruction": "FROM", "arguments": "ubuntu"},
    ]
    errors = avoid_latest_tag.check(parsed_content)
    assert len(errors) == 0  # No error because no 'latest' tag is explicitly used
