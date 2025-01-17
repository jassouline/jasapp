import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0011(BaseRule):
    """
    Rule to detect if containers have added capabilities that are not minimized.
    """
    rule_type = "kubernetes"

    def __init__(self, allowed_capabilities=None):
        super().__init__(
            friendly_name="AddedCapabilitiesMinimized",
            name="K8S-SEC-0011",
            description="Containers should drop all capabilities and add only those required.",
            severity="info",
        )
        self.allowed_capabilities = set(allowed_capabilities) if allowed_capabilities else None

    def check(self, resources):
        """
        Checks if containers have added capabilities that are not minimized.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"]:
                if resource["kind"] == "Pod":
                    containers = resource["spec"].get("containers", [])
                    init_containers = resource["spec"].get("initContainers", [])
                else:
                    containers = resource["spec"].get("template", {}).get("spec", {}).get("containers", [])
                    init_containers = resource["spec"].get("template", {}).get("spec", {}).get("initContainers", [])
                for container in containers + init_containers:
                    capabilities = container.get("securityContext", {}).get("capabilities", {}).get("add", [])
                    if self.allowed_capabilities is None and capabilities:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' adds capabilities when no list is authorized",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })
                    elif self.allowed_capabilities is not None:
                        for cap in capabilities:
                            if cap not in self.allowed_capabilities:
                                errors.append({
                                    "line": resource["metadata"].get("lineNumber", "N/A"),
                                    "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' adds capability '{cap}' which is not in the allowed list.",
                                    "severity": self.severity,
                                    "kind": resource["kind"],
                                })

        return errors


@pytest.fixture
def added_capabilities_minimized():
    return K8S_SEC_0011(allowed_capabilities=["NET_ADMIN", "SYS_TIME"])


@pytest.fixture
def added_capabilities_all_forbidden():
    return K8S_SEC_0011()


def test_detects_disallowed_capability_in_pod(added_capabilities_minimized):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image",
                        "securityContext": {
                            "capabilities": {
                                "add": ["NET_ADMIN", "SYS_PTRACE"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = added_capabilities_minimized.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "adds capability 'SYS_PTRACE'" in errors[0]["message"]


def test_detects_disallowed_capability_in_deployment(added_capabilities_minimized):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deployment", "lineNumber": 1},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "my-container",
                                "image": "my-image",
                                "securityContext": {
                                    "capabilities": {
                                        "add": ["SYS_TIME", "AUDIT_CONTROL"]
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = added_capabilities_minimized.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "adds capability 'AUDIT_CONTROL'" in errors[0]["message"]


def test_allows_allowed_capabilities(added_capabilities_minimized):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image",
                        "securityContext": {
                            "capabilities": {
                                "add": ["NET_ADMIN", "SYS_TIME"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = added_capabilities_minimized.check(parsed_content)
    assert len(errors) == 0


def test_detects_forbidden_capabilities_in_pod(added_capabilities_all_forbidden):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image",
                        "securityContext": {
                            "capabilities": {
                                "add": ["NET_ADMIN", "SYS_PTRACE"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = added_capabilities_all_forbidden.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "adds capabilities when no list is authorized" in errors[0]["message"]
