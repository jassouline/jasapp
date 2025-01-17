import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0007(BaseRule):
    """
    Rule to detect if Pods or PodSecurityPolicies allow privileged containers.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="PrivilegedContainerAllowed",
            name="K8S-SEC-0007",
            description="Containers should not be privileged.",
            severity="error",
        )

    def check(self, resources):
        """
        Checks if any Pod or PodSecurityPolicy allows privileged containers.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] == "PodSecurityPolicy":
                if resource["spec"].get("privileged", False):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"PodSecurityPolicy '{resource['metadata'].get('name', 'Unknown')}' allows privileged containers.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })
            elif resource["kind"] in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"]:
                if resource["kind"] == "Pod":
                    containers = resource["spec"].get("containers", [])
                    init_containers = resource["spec"].get("initContainers", [])
                else:
                    containers = resource["spec"].get("template", {}).get("spec", {}).get("containers", [])
                    init_containers = resource["spec"].get("template", {}).get("spec", {}).get("initContainers", [])

                for container in containers + init_containers:
                    if container.get("securityContext", {}).get("privileged", False):
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is privileged.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def privileged_container():
    return K8S_SEC_0007()


def test_pod_security_policy_allows_privileged(privileged_container):
    parsed_content = [
        {
            "apiVersion": "policy/v1beta1",
            "kind": "PodSecurityPolicy",
            "metadata": {"name": "privileged", "lineNumber": 1},
            "spec": {"privileged": True},
        }
    ]
    errors = privileged_container.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "allows privileged containers" in errors[0]["message"]


def test_pod_allows_privileged(privileged_container):
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
    assert "is privileged" in errors[0]["message"]


def test_init_container_allows_privileged(privileged_container):
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
                            "privileged": True
                        }
                    }
                ],
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image",
                    }
                ]
            }
        }
    ]
    errors = privileged_container.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-init-container' in Pod 'my-pod' is privileged" in errors[0]["message"]


def test_deployment_allows_privileged(privileged_container):
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
    assert "is privileged" in errors[0]["message"]


def test_pod_security_policy_disallows_privileged(privileged_container):
    parsed_content = [
        {
            "apiVersion": "policy/v1beta1",
            "kind": "PodSecurityPolicy",
            "metadata": {"name": "restricted", "lineNumber": 1},
            "spec": {"privileged": False},
        }
    ]
    errors = privileged_container.check(parsed_content)
    assert len(errors) == 0


def test_pod_disallows_privileged(privileged_container):
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


def test_deployment_disallows_privileged(privileged_container):
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
                                "name": "my-non-privileged-container",
                                "image": "my-image",
                                "securityContext": {
                                    "privileged": False
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = privileged_container.check(parsed_content)
    assert len(errors) == 0
