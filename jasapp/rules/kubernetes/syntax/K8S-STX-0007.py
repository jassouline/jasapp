import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_STX_0007(BaseRule):
    """
    Rule to detect if containers don't have a readiness probe configured.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="ReadinessProbeMissing",
            name="K8S-STX-0007",
            description="Containers should have a readiness probe configured.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if containers have a readiness probe configured.

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
                    if "readinessProbe" not in container:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not have a readiness probe configured.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def readiness_probe_missing():
    return K8S_STX_0007()


def test_detects_missing_readiness_probe_in_pod(readiness_probe_missing):
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
    errors = readiness_probe_missing.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not have a readiness probe configured" in errors[0]["message"]


def test_detects_missing_readiness_probe_in_deployment(readiness_probe_missing):
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
    errors = readiness_probe_missing.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not have a readiness probe configured" in errors[0]["message"]


def test_allows_pod_with_readiness_probe(readiness_probe_missing):
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
                        "readinessProbe": {
                            "httpGet": {
                                "path": "/ready",
                                "port": 8080,
                            },
                            "initialDelaySeconds": 5,
                            "periodSeconds": 10
                        }
                    }
                ]
            }
        }
    ]
    errors = readiness_probe_missing.check(parsed_content)
    assert len(errors) == 0
