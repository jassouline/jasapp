import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0001(BaseRule):
    """
    Rule to detect if Pods or PodSecurityPolicies allow sharing the host's Process ID namespace.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="HostPIDSharingEnabled",
            name="K8S-SEC-0001",
            description="Containers should not be allowed to share the host's process ID namespace.",
            severity="error",
        )

    def check(self, resources):
        """
        Checks if any Pod or PodSecurityPolicy allows sharing the host's PID namespace.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] == "PodSecurityPolicy":
                if resource["spec"].get("hostPID", False):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"PodSecurityPolicy '{resource['metadata'].get('name', 'Unknown')}' allows sharing the host's PID namespace.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })
            elif resource["kind"] in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"]:
                spec = resource["spec"]
                if resource["kind"] != "Pod":
                    spec = resource["spec"].get("template", {}).get("spec", {})

                if spec.get("hostPID", False):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"{resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' allows sharing the host's PID namespace.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

                containers = spec.get("containers", [])
                init_containers = spec.get("initContainers", [])
                for container in containers + init_containers:
                    security_context = container.get("securityContext", {})
                    if security_context.get("hostPID", False):
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' allows sharing the host's PID namespace.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def host_pid_sharing_enabled():
    return K8S_SEC_0001()


def test_pod_security_policy_allows_host_pid(host_pid_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "policy/v1beta1",
            "kind": "PodSecurityPolicy",
            "metadata": {"name": "privileged", "lineNumber": 1},
            "spec": {"hostPID": True},
        }
    ]
    errors = host_pid_sharing_enabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "allows sharing the host's PID namespace" in errors[0]["message"]


def test_pod_allows_host_pid(host_pid_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "hostPID": True,
                "containers": [
                  {
                    "name": "my-container",
                  }
                ]
            }
        }
    ]
    errors = host_pid_sharing_enabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "allows sharing the host's PID namespace" in errors[0]["message"]


def test_container_allows_host_pid(host_pid_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                  {
                    "name": "my-container",
                    "securityContext": {
                        "hostPID": True
                    }
                  }
                ]
            }
        }
    ]
    errors = host_pid_sharing_enabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "allows sharing the host's PID namespace" in errors[0]["message"]


def test_deployment_allows_host_pid(host_pid_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deployment", "lineNumber": 1},
            "spec": {"template": {"spec": {"hostPID": True,
                                           "containers": [
                                              {
                                                "name": "my-container",
                                              }
                                            ]}}},
        }
    ]
    errors = host_pid_sharing_enabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "allows sharing the host's PID namespace" in errors[0]["message"]


def test_pod_security_policy_disallows_host_pid(host_pid_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "policy/v1beta1",
            "kind": "PodSecurityPolicy",
            "metadata": {"name": "restricted", "lineNumber": 1},
            "spec": {"hostPID": False},
        }
    ]
    errors = host_pid_sharing_enabled.check(parsed_content)
    assert len(errors) == 0


def test_pod_disallows_host_pid(host_pid_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {"hostPID": False, "containers": [{"name": "my-container"}]},
        }
    ]
    errors = host_pid_sharing_enabled.check(parsed_content)
    assert len(errors) == 0


def test_deployment_disallows_host_pid(host_pid_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deployment", "lineNumber": 1},
            "spec": {"template": {"spec": {"hostPID": False, "containers": [{"name": "my-container"}]}}},
        }
    ]
    errors = host_pid_sharing_enabled.check(parsed_content)
    assert len(errors) == 0
