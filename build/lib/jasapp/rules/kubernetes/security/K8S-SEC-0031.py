import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0031(BaseRule):
    """
    Rule to detect if containers have the NET_RAW capability without explicitly dropping it or dropping ALL.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="NetRawCapabilityNotDropped",
            name="K8S-SEC-0031",
            description="Containers should drop the NET_RAW capability or drop ALL capabilities.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if containers have the NET_RAW capability without explicitly dropping it or dropping ALL.

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

                    if "NET_RAW" in added_capabilities and "ALL" not in dropped_capabilities:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' has NET_RAW capability without dropping ALL.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def net_raw_capability_not_dropped():
    return K8S_SEC_0031()


def test_detects_net_raw_capability_in_pod(net_raw_capability_not_dropped):
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
                                "add": ["NET_RAW"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = net_raw_capability_not_dropped.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "has NET_RAW capability without dropping ALL" in errors[0]["message"]


def test_detects_net_raw_capability_in_deployment(net_raw_capability_not_dropped):
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
                                        "add": ["NET_RAW"]
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = net_raw_capability_not_dropped.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "has NET_RAW capability without dropping ALL" in errors[0]["message"]


def test_allows_pod_with_drop_all(net_raw_capability_not_dropped):
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
    errors = net_raw_capability_not_dropped.check(parsed_content)
    assert len(errors) == 0


def test_allows_pod_with_net_raw_dropped(net_raw_capability_not_dropped):
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
                                "drop": ["NET_RAW"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = net_raw_capability_not_dropped.check(parsed_content)
    assert len(errors) == 0
