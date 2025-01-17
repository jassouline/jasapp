import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0008(BaseRule):
    """
    Rule to detect if containers are not using a read-only root filesystem.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="ReadOnlyRootFilesystemNotUsed",
            name="K8S-SEC-0008",
            description="Containers should use a read-only root filesystem.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if containers are using a read-only root filesystem.

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
                    readonly_fs = security_context.get("readOnlyRootFilesystem")
                    if not readonly_fs:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not use a read-only root filesystem.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def read_only_root_filesystem_not_used():
    return K8S_SEC_0008()


def test_detects_non_readonly_filesystem_in_pod(read_only_root_filesystem_not_used):
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
                            "readOnlyRootFilesystem": False
                        }
                    }
                ]
            }
        }
    ]
    errors = read_only_root_filesystem_not_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not use a read-only root filesystem" in errors[0]["message"]


def test_detects_non_readonly_filesystem_in_deployment(read_only_root_filesystem_not_used):
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
                                    "readOnlyRootFilesystem": False
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = read_only_root_filesystem_not_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not use a read-only root filesystem" in errors[0]["message"]


def test_detects_non_readonly_filesystem_with_init_container(read_only_root_filesystem_not_used):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "initContainers": [
                    {
                        "name": "my-init-container",
                        "image": "my-init-image",
                        "securityContext": {
                            "readOnlyRootFilesystem": False
                        }
                    }
                ],
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
    errors = read_only_root_filesystem_not_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-init-container' in Pod 'my-pod' does not use a read-only root filesystem" in errors[0]["message"]


def test_allows_readonly_filesystem(read_only_root_filesystem_not_used):
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
                            "readOnlyRootFilesystem": True
                        }
                    }
                ]
            }
        }
    ]
    errors = read_only_root_filesystem_not_used.check(parsed_content)
    assert len(errors) == 0


def test_allows_pod_without_security_context(read_only_root_filesystem_not_used):
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
    errors = read_only_root_filesystem_not_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not use a read-only root filesystem" in errors[0]["message"]
