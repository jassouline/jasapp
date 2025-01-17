import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_PERF_0001(BaseRule):
    """
    Rule to detect if CPU limits are not set for containers in Kubernetes resources.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="CPULimitsMissing",
            name="K8S-PERF-0001",
            description="CPU limits are not set for container.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if CPU limits are set for containers in Kubernetes resources.

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
                    cpu_limit = container.get("resources", {}).get("limits", {}).get("cpu")
                    if not cpu_limit:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not have CPU limits set.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def cpu_limits_not_set():
    return K8S_PERF_0001()


def test_detects_missing_cpu_limits_in_pod(cpu_limits_not_set):
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
    errors = cpu_limits_not_set.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-container' in Pod 'my-pod' does not have CPU limits set." in errors[0]["message"]


def test_detects_missing_cpu_limits_in_deployment(cpu_limits_not_set):
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
    errors = cpu_limits_not_set.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-container' in Deployment 'my-deployment' does not have CPU limits set." in errors[0]["message"]


def test_allows_cpu_limits_in_pod(cpu_limits_not_set):
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
                            "limits": {
                                "cpu": "100m"
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = cpu_limits_not_set.check(parsed_content)
    assert len(errors) == 0


def test_allows_cpu_limits_in_deployment(cpu_limits_not_set):
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
                                    "limits": {
                                        "cpu": "200m"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = cpu_limits_not_set.check(parsed_content)
    assert len(errors) == 0
