import pytest
from jasapp.rules.base_rule import BaseRule


class STX0025(BaseRule):
    """
    Rule to ensure only allowed registries are used in the FROM image.
    """
    rule_type = "dockerfile"

    def __init__(self, allowed_registries=None):
        super().__init__(
            friendly_name="UseOnlyAllowedRegistriesInFrom",
            hadolint="DL3026",
            name="STX0025",
            description="Use only an allowed registry in the FROM image",
            severity="error",
        )
        # If allowed_registries is None, no restrictions are applied.
        # If allowed_registries is an empty set, only docker.io and hub.docker.com are allowed.
        self.allowed_registries = set(allowed_registries) if allowed_registries is not None else None

    def check(self, instructions):
        """
        Checks if only allowed registries are used in FROM instructions.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        aliases = set()

        for instr in instructions:
            if instr["instruction"] == "FROM":
                arguments = instr["arguments"].split()
                image = arguments[0]

                if len(arguments) > 2 and arguments[-2].upper() == "AS":
                    alias = arguments[-1]
                    aliases.add(alias)

                if not self.is_registry_allowed(image, aliases):
                    errors.append({
                        "line": instr["line"],
                        "message": "Use only an allowed registry in the FROM image",
                        "severity": self.severity,
                        "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                    })

        return errors

    def is_registry_allowed(self, image_name, aliases):
        """
        Checks if the registry of the given image is allowed.

        Args:
            image_name (str): The name of the image, potentially including the registry.
            aliases (set) : set of aliases used

        Returns:
            bool: True if the registry is allowed, False otherwise.
        """
        # No restrictions if allowed_registries is None
        if self.allowed_registries is None:
            return True

        if image_name in aliases:
            return True
        if image_name == "scratch":
            return True

        parts = image_name.split("/")
        if len(parts) > 1:
            registry = parts[0]
        else:
            # Implicit Docker Hub image, equivalent to docker.io and hub.docker.com
            registry = "docker.io"

        # Check if the registry is allowed directly or via wildcard
        if any(self.match_registry(allowed, registry) for allowed in self.allowed_registries):
            return True

        # Special handling for docker.io and hub.docker.com equivalence
        if len(self.allowed_registries) == 0 and (registry == "docker.io" or registry == "hub.docker.com"):
            return True

        if (registry == "docker.io" or registry == "hub.docker.com") and \
           ("docker.io" in self.allowed_registries or "hub.docker.com" in self.allowed_registries):
            return True

        return False

    @staticmethod
    def match_registry(allowed, registry):
        """
        Matches a registry against an allowed pattern.

        Args:
            allowed (str): The allowed registry pattern (can include '*').
            registry (str): The registry to check.

        Returns:
            bool: True if the registry matches the pattern, False otherwise.
        """
        if allowed == "*":
            return True
        if allowed.startswith("*"):
            return registry.endswith(allowed[1:])
        if allowed.endswith("*"):
            return registry.startswith(allowed[:-1])
        return registry == allowed


@pytest.fixture
def use_only_allowed_registries_in_from():
    return STX0025(allowed_registries={"docker.io", "hub.docker.com"})


@pytest.fixture
def use_only_allowed_registries_in_from_empty():
    return STX0025(allowed_registries=set())


@pytest.fixture
def use_only_allowed_registries_in_from_none():
    return STX0025()


def test_use_only_allowed_registries_allows_docker_io(use_only_allowed_registries_in_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest"},
    ]
    errors = use_only_allowed_registries_in_from.check(parsed_content)
    assert len(errors) == 0


def test_use_only_allowed_registries_allows_explicit_docker_io(use_only_allowed_registries_in_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "docker.io/alpine:latest"},
    ]
    errors = use_only_allowed_registries_in_from.check(parsed_content)
    assert len(errors) == 0


def test_use_only_allowed_registries_allows_explicit_hub_docker_com(use_only_allowed_registries_in_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "hub.docker.com/alpine:latest"},
    ]
    errors = use_only_allowed_registries_in_from.check(parsed_content)
    assert len(errors) == 0


def test_use_only_allowed_registries_detects_disallowed_registry(use_only_allowed_registries_in_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "otherregistry.com/myimage:latest"},
    ]
    errors = use_only_allowed_registries_in_from.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert errors[0]["message"] == "Use only an allowed registry in the FROM image"


def test_use_only_allowed_registries_allows_scratch(use_only_allowed_registries_in_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "scratch"},
    ]
    errors = use_only_allowed_registries_in_from.check(parsed_content)
    assert len(errors) == 0


def test_use_only_allowed_registries_no_restrictions(use_only_allowed_registries_in_from_none):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "otherregistry.com/myimage:latest"},
    ]
    errors = use_only_allowed_registries_in_from_none.check(parsed_content)
    assert len(errors) == 0


def test_use_only_allowed_registries_empty_restriction_allows_docker_io(use_only_allowed_registries_in_from_empty):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "docker.io/alpine:latest"},
    ]
    errors = use_only_allowed_registries_in_from_empty.check(parsed_content)
    assert len(errors) == 0


def test_use_only_allowed_registries_empty_restriction_allows_hub_docker_com(use_only_allowed_registries_in_from_empty):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "hub.docker.com/alpine:latest"},
    ]
    errors = use_only_allowed_registries_in_from_empty.check(parsed_content)
    assert len(errors) == 0


def test_use_only_allowed_registries_empty_restriction_allows_implicit(use_only_allowed_registries_in_from_empty):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "alpine:latest"},
    ]
    errors = use_only_allowed_registries_in_from_empty.check(parsed_content)
    assert len(errors) == 0


def test_use_only_allowed_registries_empty_restriction_detects_disallowed_registry(use_only_allowed_registries_in_from_empty):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "otherregistry.com/myimage:latest"},
    ]
    errors = use_only_allowed_registries_in_from_empty.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert errors[0]["message"] == "Use only an allowed registry in the FROM image"


def test_use_only_allowed_registries_allows_previous_alias(use_only_allowed_registries_in_from):
    parsed_content = [
        {"line": 1, "instruction": "FROM", "arguments": "docker.io/alpine:latest as builder"},
        {"line": 2, "instruction": "FROM", "arguments": "builder"}
    ]
    errors = use_only_allowed_registries_in_from.check(parsed_content)
    assert len(errors) == 0
