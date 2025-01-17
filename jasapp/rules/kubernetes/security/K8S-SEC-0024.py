import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0024(BaseRule):
    """
    Rule to detect if containers have the `CAP_SYS_ADMIN` capability.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="CapSysAdminAdded",
            name="K8S-SEC-0024",
            description="Containers should not add the `CAP_SYS_ADMIN` capability.",
            severity="error",
        )

    def check(self, resources):
        """
        Checks if containers have the `CAP_SYS_ADMIN` capability.

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
                    capabilities = container.get("securityContext", {}).get("capabilities", {}).get("add", [])
                    if "SYS_ADMIN" in capabilities or "CAP_SYS_ADMIN" in capabilities:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is granted the `CAP_SYS_ADMIN` capability.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def cap_sys_admin_added():
    return K8S_SEC_0024()


def test_detects_cap_sys_admin_in_pod(cap_sys_admin_added):
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
                                "add": ["CAP_SYS_ADMIN"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = cap_sys_admin_added.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is granted the `CAP_SYS_ADMIN` capability" in errors[0]["message"]


def test_detects_cap_sys_admin_in_deployment(cap_sys_admin_added):
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
                                    "capabilities": {
                                        "add": ["CAP_SYS_ADMIN"]
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = cap_sys_admin_added.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is granted the `CAP_SYS_ADMIN` capability" in errors[0]["message"]


def test_detects_cap_sys_admin_without_cap_in_pod(cap_sys_admin_added):
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
                                "add": ["SYS_ADMIN"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = cap_sys_admin_added.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is granted the `CAP_SYS_ADMIN` capability" in errors[0]["message"]


def test_allows_pod_without_cap_sys_admin(cap_sys_admin_added):
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
                                "drop": ["CAP_SYS_ADMIN"]
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = cap_sys_admin_added.check(parsed_content)
    assert len(errors) == 0
