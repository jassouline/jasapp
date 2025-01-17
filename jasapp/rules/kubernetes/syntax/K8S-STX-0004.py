import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_STX_0004(BaseRule):
    """
    Rule to detect if Kubernetes resources are using the default namespace.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="DefaultNamespaceUsed",
            name="K8S-STX-0004",
            description="Avoid using the 'default' namespace in Kubernetes resources.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if Kubernetes resources are using the default namespace.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Service", "Ingress", "ConfigMap", "Secret"]:
                namespace = resource["metadata"].get("namespace", "default")
                if namespace == "default":
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"{resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is using the default namespace.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

        return errors


@pytest.fixture
def default_namespace_used():
    return K8S_STX_0004()


def test_detects_default_namespace_in_pod(default_namespace_used):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "default", "lineNumber": 1},
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
    errors = default_namespace_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is using the default namespace" in errors[0]["message"]


def test_detects_default_namespace_in_deployment(default_namespace_used):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deployment", "namespace": "default", "lineNumber": 1},
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
    errors = default_namespace_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is using the default namespace" in errors[0]["message"]


def test_detects_default_namespace_implicit(default_namespace_used):
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
    errors = default_namespace_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is using the default namespace" in errors[0]["message"]


def test_allows_non_default_namespace(default_namespace_used):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "namespace": "my-namespace", "lineNumber": 1},
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
    errors = default_namespace_used.check(parsed_content)
    assert len(errors) == 0
