import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0002(BaseRule):
    """
    Rule to detect if privileged containers are used in Kubernetes resources.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="PrivilegedContainer",
            name="K8S-SEC-0002",
            description="Containers should not be privileged.",
            severity="error",
        )

    def check(self, resources):
        """
        Checks if privileged containers are used in Kubernetes resources.

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
                    privileged = container.get("securityContext", {}).get("privileged", False)
                    if privileged:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is privileged.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def privileged_container():
    return K8S_SEC_0002()


def test_detects_privileged_container_in_pod(privileged_container):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-privileged-container",
                        "image": "my-image",
                        "securityContext": {
                            "privileged": True
                        }
                    }
                ]
            }
        }
    ]
    errors = privileged_container.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-privileged-container' in Pod 'my-pod' is privileged." in errors[0]["message"]


def test_detects_privileged_container_in_deployment(privileged_container):
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
                                "name": "my-privileged-container",
                                "image": "my-image",
                                "securityContext": {
                                    "privileged": True
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = privileged_container.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-privileged-container' in Deployment 'my-deployment' is privileged." in errors[0]["message"]


def test_allows_non_privileged_container(privileged_container):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-non-privileged-container",
                        "image": "my-image",
                        "securityContext": {
                            "privileged": False
                        }
                    }
                ]
            }
        }
    ]
    errors = privileged_container.check(parsed_content)
    assert len(errors) == 0


def test_allows_pod_without_security_context(privileged_container):
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
    errors = privileged_container.check(parsed_content)
    assert len(errors) == 0
