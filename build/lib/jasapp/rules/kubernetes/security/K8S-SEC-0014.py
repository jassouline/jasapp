import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0014(BaseRule):
    """
    Rule to detect if containers have the NET_RAW capability without explicitly requiring it.
    """
    rule_type = "kubernetes"

    def __init__(self, allowed_net_raw=False):
        super().__init__(
            friendly_name="NetRawCapabilityMinimized",
            name="K8S-SEC-0014",
            description="Containers should drop the NET_RAW capability unless explicitly allowed.",
            severity="info",
        )
        self.allowed_net_raw = allowed_net_raw

    def check(self, resources):
        """
        Checks if containers have the NET_RAW capability without explicitly requiring it.

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
                    capabilities = container.get("securityContext", {}).get("capabilities", {})
                    dropped_capabilities = capabilities.get("drop", [])

                    if "NET_RAW" not in dropped_capabilities and "ALL" not in dropped_capabilities and not self.allowed_net_raw:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' has NET_RAW capability. Consider dropping it.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def net_raw_capability_minimized():
    return K8S_SEC_0014()


@pytest.fixture
def net_raw_capability_allowed():
    return K8S_SEC_0014(allowed_net_raw=True)


def test_detects_net_raw_capability_in_pod(net_raw_capability_minimized):
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
    errors = net_raw_capability_minimized.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "has NET_RAW capability" in errors[0]["message"]


def test_detects_net_raw_capability_by_default(net_raw_capability_minimized):
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
                    }
                ]
            }
        }
    ]
    errors = net_raw_capability_minimized.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "has NET_RAW capability" in errors[0]["message"]


def test_allows_dropped_net_raw(net_raw_capability_minimized):
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
    errors = net_raw_capability_minimized.check(parsed_content)
    assert len(errors) == 0


def test_allows_dropped_all(net_raw_capability_minimized):
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
                                "drop": ["ALL"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = net_raw_capability_minimized.check(parsed_content)
    assert len(errors) == 0


def test_allows_net_raw_when_allowed(net_raw_capability_allowed):
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
    errors = net_raw_capability_allowed.check(parsed_content)
    assert len(errors) == 0
