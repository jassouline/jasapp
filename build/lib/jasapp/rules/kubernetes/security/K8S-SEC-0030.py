import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0030(BaseRule):
    """
    Rule to detect if containers are set to run as root.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="RootContainersMinimized",
            name="K8S-SEC-0030",
            description="Containers should not be allowed to run as root.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if containers are configured to run as root.

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
                    # Check if container is explicitly set to run as root
                    if security_context.get("runAsUser") == 0:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is allowed to run as root.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })
                        continue

                    # Check if runAsNonRoot is not set or set to False
                    if "runAsNonRoot" not in security_context or not security_context.get("runAsNonRoot"):
                        # If runAsUser is not set or is 0, and runAsNonRoot is not set to true, it's an error
                        if "runAsUser" not in security_context:
                            errors.append({
                                "line": resource["metadata"].get("lineNumber", "N/A"),
                                "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is allowed to run as root.",
                                "severity": self.severity,
                                "kind": resource["kind"],
                            })

        return errors


@pytest.fixture
def root_containers_allowed():
    return K8S_SEC_0030()


def test_detects_root_container_in_pod(root_containers_allowed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-root-container",
                        "image": "my-image",
                    }
                ]
            }
        }
    ]
    errors = root_containers_allowed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is allowed to run as root" in errors[0]["message"]


def test_detects_root_container_in_deployment(root_containers_allowed):
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
                                "name": "my-root-container",
                                "image": "my-image",
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = root_containers_allowed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is allowed to run as root" in errors[0]["message"]


def test_allows_non_root_container_runasnonroot(root_containers_allowed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-non-root-container",
                        "image": "my-image",
                        "securityContext": {
                            "runAsNonRoot": True
                        }
                    }
                ]
            }
        }
    ]
    errors = root_containers_allowed.check(parsed_content)
    assert len(errors) == 0


def test_allows_non_root_container_runasuser(root_containers_allowed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-non-root-container",
                        "image": "my-image",
                        "securityContext": {
                            "runAsUser": 1000
                        }
                    }
                ]
            }
        }
    ]
    errors = root_containers_allowed.check(parsed_content)
    assert len(errors) == 0
