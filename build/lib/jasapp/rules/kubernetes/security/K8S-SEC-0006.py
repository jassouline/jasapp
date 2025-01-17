import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0006(BaseRule):
    """
    Rule to detect if containers are running with allowPrivilegeEscalation set to true.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="AllowPrivilegeEscalationDisallowed",
            name="K8S-SEC-0006",
            description="Containers should not allow privilege escalation.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if containers are running with allowPrivilegeEscalation set to true.

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
                    # Check if allowPrivilegeEscalation is explicitly set to false
                    sec_context = container.get("securityContext")

                    if sec_context is None or sec_context.get("allowPrivilegeEscalation", True):
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' has allowPrivilegeEscalation set to true or not set.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def allow_privilege_escalation():
    return K8S_SEC_0006()


def test_detects_privilege_escalation_in_pod(allow_privilege_escalation):
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
                            "allowPrivilegeEscalation": True
                        }
                    }
                ]
            }
        }
    ]
    errors = allow_privilege_escalation.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "has allowPrivilegeEscalation set to true" in errors[0]["message"]


def test_detects_privilege_escalation_in_deployment(allow_privilege_escalation):
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
                                    "allowPrivilegeEscalation": True
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = allow_privilege_escalation.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "has allowPrivilegeEscalation set to true" in errors[0]["message"]


def test_detects_privilege_escalation_with_init_container(allow_privilege_escalation):
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
                            "allowPrivilegeEscalation": True
                        }
                    }
                ],
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image",
                        "securityContext": {
                            "allowPrivilegeEscalation": True
                        }
                    }
                ]
            }
        }
    ]
    errors = allow_privilege_escalation.check(parsed_content)
    assert len(errors) == 2
    assert errors[0]["line"] == 1
    assert "Container 'my-container' in Pod 'my-pod' has allowPrivilegeEscalation set to true" in errors[0]["message"]
    assert errors[1]["line"] == 1
    assert "Container 'my-init-container' in Pod 'my-pod' has allowPrivilegeEscalation set to true" in errors[1]["message"]


def test_allows_non_privileged_container(allow_privilege_escalation):
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
                            "allowPrivilegeEscalation": False
                        }
                    }
                ]
            }
        }
    ]
    errors = allow_privilege_escalation.check(parsed_content)
    assert len(errors) == 0


def test_allows_pod_without_security_context(allow_privilege_escalation):
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
    errors = allow_privilege_escalation.check(parsed_content)
    assert len(errors) == 1
