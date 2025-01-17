import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0010(BaseRule):
    """
    Rule to detect if containers have added capabilities beyond the allowed list.
    """
    rule_type = "kubernetes"

    def __init__(self, allowed_capabilities=None):
        super().__init__(
            friendly_name="AddedCapabilities",
            name="K8S-SEC-0010",
            description="Containers should only add specific capabilities.",
            severity="info",
        )
        self.allowed_capabilities = set(allowed_capabilities) if allowed_capabilities else set()

    def check(self, resources):
        """
        Checks if containers have added capabilities beyond the allowed list.

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
def added_capabilities():
    return K8S_SEC_0010(allowed_capabilities=["NET_ADMIN", "SYS_TIME"])


def test_detects_disallowed_capability_in_pod(added_capabilities):
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
    errors = added_capabilities.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-container' in Pod 'my-pod' adds capability 'SYS_PTRACE'" in errors[0]["message"]


def test_detects_disallowed_capability_in_deployment(added_capabilities):
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
    errors = added_capabilities.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-container' in Deployment 'my-deployment' adds capability 'AUDIT_CONTROL'" in errors[0]["message"]


def test_allows_allowed_capabilities(added_capabilities):
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
    errors = added_capabilities.check(parsed_content)
    assert len(errors) == 0
