import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0022(BaseRule):
    """
    Rule to detect if containers have added capabilities that are not minimized.
    """
    rule_type = "kubernetes"

    def __init__(self, allowed_capabilities=None):
        super().__init__(
            friendly_name="AddedCapabilitiesMinimized",
            name="K8S-SEC-0022",
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
                    security_context = container.get("securityContext", {})
                    capabilities = security_context.get("capabilities", {})
                    added_capabilities = capabilities.get("add", [])
                    dropped_capabilities = capabilities.get("drop", [])

                    if "ALL" in dropped_capabilities:
                        continue

                    if self.allowed_capabilities is None and added_capabilities:
                        message = "adds capabilities but does not drop 'ALL'. No capabilities are allowed by default."
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' " + message,
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })
                    elif self.allowed_capabilities is not None:
                        for cap in added_capabilities:
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
    return K8S_SEC_0022(allowed_capabilities=["NET_ADMIN", "SYS_TIME"])


@pytest.fixture
def added_capabilities_all_forbidden():
    return K8S_SEC_0022()


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


def test_allows_pod_with_drop_all(added_capabilities_minimized):
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
                                "drop": ["ALL"],
                                "add": ["NET_BIND_SERVICE"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = added_capabilities_minimized.check(parsed_content)
    assert len(errors) == 0


def test_allows_pod_with_allowed_capabilities(added_capabilities_minimized):
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


def test_detects_added_capability_when_all_forbidden(added_capabilities_all_forbidden):
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
                                "add": ["NET_BIND_SERVICE"]
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
    assert "adds capabilities but does not drop 'ALL'" in errors[0]["message"]
