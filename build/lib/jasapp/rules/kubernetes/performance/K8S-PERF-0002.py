import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_PERF_0002(BaseRule):
    """
    Rule to detect if memory requests are not set for containers in Kubernetes resources.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="MemoryRequestsMissing",
            name="K8S-PERF-0002",
            description="Memory requests are not set for container.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if memory requests are set for containers in Kubernetes resources.

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
                    memory_request = container.get("resources", {}).get("requests", {}).get("memory")
                    if not memory_request:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not have memory requests set.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def memory_requests_not_set():
    return K8S_PERF_0002()


def test_detects_missing_memory_requests_in_pod(memory_requests_not_set):
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
    errors = memory_requests_not_set.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-container' in Pod 'my-pod' does not have memory requests set." in errors[0]["message"]


def test_detects_missing_memory_requests_in_deployment(memory_requests_not_set):
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
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = memory_requests_not_set.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-container' in Deployment 'my-deployment' does not have memory requests set." in errors[0]["message"]


def test_allows_memory_requests_in_pod(memory_requests_not_set):
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
                        "resources": {
                            "requests": {
                                "memory": "64Mi"
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = memory_requests_not_set.check(parsed_content)
    assert len(errors) == 0


def test_allows_memory_requests_in_deployment(memory_requests_not_set):
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
                                "resources": {
                                    "requests": {
                                        "memory": "128Mi"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = memory_requests_not_set.check(parsed_content)
    assert len(errors) == 0
