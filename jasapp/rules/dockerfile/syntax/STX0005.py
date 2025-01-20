import pytest
from jasapp.rules.base_rule import BaseRule


class STX0005(BaseRule):
    """
    Rule to ensure that images used in FROM instructions are explicitly tagged.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="AlwaysTagImage",
            hadolint="DL3006",
            name="STX0005",
            description="Always tag the version of an image explicitly in FROM instructions.",
            severity="warning",
        )

    def check(self, instructions):
        """
        Checks if FROM instructions explicitly tag the image version.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        seen_aliases = set()

        for instr in instructions:
            if instr["instruction"] == "FROM":
                parts = instr["arguments"].split()
                image = parts[0]
                alias = parts[2] if len(parts) > 2 and parts[1].upper() == "AS" else None

                # Record aliases
                if alias:
                    seen_aliases.add(alias)

                # Skip "scratch" and images with a digest
                if image == "scratch" or "@" in image:
                    continue

                # Check if the image is tagged
                if ":" not in image and image not in seen_aliases and not image.startswith("$"):
                    errors.append({
                        "line": instr["line"],
                        "message": f"Image '{image}' is not tagged. Always tag the version explicitly (e.g., 'image:tag').",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors


@pytest.fixture
def always_tag_image():
    return STX0005()


def test_always_tag_image_detects_untagged_images(always_tag_image):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "ubuntu"},
        {"line": 2, "instruction": "FROM", "arguments": "alpine"},
    ]
    errors = always_tag_image.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["message"] == "Image 'ubuntu' is not tagged. Always tag the version explicitly (e.g., 'image:tag')."
    assert errors[0]["line"] == 1
    assert errors[1]["message"] == "Image 'alpine' is not tagged. Always tag the version explicitly (e.g., 'image:tag')."
    assert errors[1]["line"] == 2


def test_always_tag_image_allows_tagged_images(always_tag_image):
    parsed_content = [
        {"line": 3, "instruction": "FROM", "arguments": "ubuntu:20.04"},
        {"line": 4, "instruction": "FROM", "arguments": "alpine:3.14"},
    ]
    errors = always_tag_image.check(parsed_content)
    assert len(errors) == 0


def test_always_tag_image_allows_scratch_and_digest(always_tag_image):
    parsed_content = [
        {"line": 5, "instruction": "FROM", "arguments": "scratch"},
        {"line": 6, "instruction": "FROM", "arguments": "alpine@sha256:abcdef"},
    ]
    errors = always_tag_image.check(parsed_content)
    assert len(errors) == 0


def test_always_tag_image_allows_aliases(always_tag_image):
    parsed_content = [
        {"line": 7, "instruction": "FROM", "arguments": "ubuntu:20.04 AS builder"},
        {"line": 8, "instruction": "FROM", "arguments": "builder"},
    ]
    errors = always_tag_image.check(parsed_content)
    assert len(errors) == 0
