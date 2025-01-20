import pytest
from jasapp.rules.base_rule import BaseRule


class SEC0005(BaseRule):
    """
    Rule to detect the mounting of sensitive directories (/dev, /proc, /sys) in Docker volumes.
    """
    rule_type = "dockerfile"

    def __init__(self):
        super().__init__(
            friendly_name="AvoidSensitiveDirMount",
            name="SEC0005",
            description="Avoid mounting sensitive directories in Docker volumes",
            severity="error",
        )

    def check(self, instructions):
        """
        Checks if `VOLUME` instructions mount sensitive directories.

        Args:
            instructions (list): A list of dictionaries containing parsed Dockerfile instructions.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, and severity.
        """
        errors = []
        sensitive_dirs = ["/dev", "/proc", "/sys"]

        for instr in instructions:
            if instr["instruction"] == "VOLUME":
                volumes = []
                if instr["arguments"].startswith("["):
                    # JSON format
                    volumes = [v.strip().strip('"').strip("'") for v in instr["arguments"][1:-1].split(",")]
                else:
                    # Regular format
                    volumes = instr["arguments"].split()
                for volume in volumes:
                    # Extract the destination path from the volume argument
                    destination_path = volume.split(':', 1)[-1] if ':' in volume else volume

                    destination_path = destination_path.strip("'\"")
                    print(destination_path)
                    for sensitive_dir in sensitive_dirs:
                        if sensitive_dir in destination_path:
                            errors.append({
                                "line": instr["line"],
                                "message": f"Avoid mounting sensitive directory '{destination_path}' in a volume.",
                                "severity": self.severity,
                                "doc_link": f"https://github.com/jassouline/jasapp/wiki/{self.name}"
                            })

        return errors


@pytest.fixture
def avoid_sensitive_dir_mount():
    return SEC0005()


def test_sensitive_dir_mount_detects_dev(avoid_sensitive_dir_mount):
    parsed_content = [
        {"line": 1, "instruction": "VOLUME", "arguments": "/dev:/dev"},
    ]
    errors = avoid_sensitive_dir_mount.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Avoid mounting sensitive directory '/dev'" in errors[0]["message"]


def test_sensitive_dir_mount_detects_proc(avoid_sensitive_dir_mount):
    parsed_content = [
        {"line": 1, "instruction": "VOLUME", "arguments": "/proc:/host/proc"},
    ]
    errors = avoid_sensitive_dir_mount.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Avoid mounting sensitive directory '/host/proc'" in errors[0]["message"]


def test_sensitive_dir_mount_detects_sys(avoid_sensitive_dir_mount):
    parsed_content = [
        {"line": 1, "instruction": "VOLUME", "arguments": "/sys:/host/sys"},
    ]
    errors = avoid_sensitive_dir_mount.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Avoid mounting sensitive directory '/host/sys'" in errors[0]["message"]


def test_sensitive_dir_mount_allows_non_sensitive_dir(avoid_sensitive_dir_mount):
    parsed_content = [
        {"line": 1, "instruction": "VOLUME", "arguments": "/app"},
    ]
    errors = avoid_sensitive_dir_mount.check(parsed_content)
    assert len(errors) == 0


def test_sensitive_dir_mount_detects_multiple_sensitive_dirs(avoid_sensitive_dir_mount):
    parsed_content = [
        {"line": 1, "instruction": "VOLUME", "arguments": "/dev /proc /sys"},
    ]
    errors = avoid_sensitive_dir_mount.check(parsed_content)
    assert len(errors) == 3


def test_sensitive_dir_mount_detects_multiple_sensitive_dirs_json(avoid_sensitive_dir_mount):
    parsed_content = [
        {"line": 1, "instruction": "VOLUME", "arguments": "[\"/dev\", \"/proc\", \"/sys\"]"},
    ]
    errors = avoid_sensitive_dir_mount.check(parsed_content)
    assert len(errors) == 3
