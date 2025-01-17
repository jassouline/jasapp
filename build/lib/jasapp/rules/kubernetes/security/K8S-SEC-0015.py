import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0015(BaseRule):
    """
    Rule to detect if securityContext is not applied to pods and containers.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="SecurityContextMissing",
            name="K8S-SEC-0015",
            description="`securityContext` is not applied to pods or containers.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if securityContext is applied to pods and containers.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"]:
                if resource["kind"] == "Pod":
                    spec = resource["spec"]
                    containers = spec.get("containers", [])
                    init_containers = spec.get("initContainers", [])
                else:
                    spec = resource["spec"].get("template", {}).get("spec", {})
                    containers = spec.get("containers", [])
                    init_containers = spec.get("initContainers", [])

                # Check if securityContext is missing at the Pod level
                if not spec.get("securityContext"):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"PodSecurityContext not defined for {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}'.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

                # Check if securityContext is missing at the container level
                for container in containers + init_containers:
                    if not container.get("securityContext"):
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not have a securityContext defined.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def security_context_missing():
    return K8S_SEC_0015()


def test_detects_missing_security_context_in_pod(security_context_missing):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image"
                    }
                ]
            }
        }
    ]
    errors = security_context_missing.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert "PodSecurityContext not defined" in errors[0]["message"]
    assert "does not have a securityContext defined" in errors[1]["message"]


def test_detects_missing_security_context_in_deployment(security_context_missing):
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
                                "image": "my-image"
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = security_context_missing.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert "PodSecurityContext not defined" in errors[0]["message"]
    assert "does not have a securityContext defined" in errors[1]["message"]


def test_allows_security_context_in_pod(security_context_missing):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "securityContext": {
                    "runAsNonRoot": True
                },
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image",
                        "securityContext": {
                            "readOnlyRootFilesystem": True
                        }
                    }
                ]
            }
        }
    ]
    errors = security_context_missing.check(parsed_content)
    assert len(errors) == 0
