import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_STX_0006(BaseRule):
    """
    Rule to detect if containers don't have a liveness probe configured.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="LivenessProbeMissing",
            name="K8S-STX-0006",
            description="Containers should have a liveness probe configured.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if containers have a liveness probe configured.

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
                    if "livenessProbe" not in container:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not have a liveness probe configured.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def liveness_probe_missing():
    return K8S_STX_0006()


def test_detects_missing_liveness_probe_in_pod(liveness_probe_missing):
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
    errors = liveness_probe_missing.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not have a liveness probe configured" in errors[0]["message"]


def test_detects_missing_liveness_probe_in_deployment(liveness_probe_missing):
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
    errors = liveness_probe_missing.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not have a liveness probe configured" in errors[0]["message"]


def test_allows_pod_with_liveness_probe(liveness_probe_missing):
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
                        "livenessProbe": {
                            "httpGet": {
                                "path": "/healthz",
                                "port": 8080,
                            },
                            "initialDelaySeconds": 15,
                            "periodSeconds": 20
                        }
                    }
                ]
            }
        }
    ]
    errors = liveness_probe_missing.check(parsed_content)
    assert len(errors) == 0
