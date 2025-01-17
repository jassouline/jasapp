import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0016(BaseRule):
    """
    Rule to detect if seccomp profile is not set to `RuntimeDefault` or `DockerDefault` in Pods and containers.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="SeccompProfileNotSet",
            name="K8S-SEC-0016",
            description="Seccomp profile should be set to `RuntimeDefault` or `DockerDefault`.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if seccomp profile is set to `RuntimeDefault` or `DockerDefault` in Pods and containers.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"]:
                spec = resource["spec"]
                if resource["kind"] != "Pod":
                    spec = resource["spec"].get("template", {}).get("spec", {})

                # Check Pod-level security context
                pod_security_context = spec.get("securityContext", {})
                if not self.is_valid_seccomp_profile(pod_security_context):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"Pod '{resource['metadata'].get('name', 'Unknown')}' in {resource['kind']} does not have a valid seccomp profile.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

                # Check container-level security context
                containers = spec.get("containers", [])
                init_containers = spec.get("initContainers", [])
                for container in containers + init_containers:
                    security_context = container.get("securityContext", {})
                    if not self.is_valid_seccomp_profile(security_context):
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not have a valid seccomp profile.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors

    def is_valid_seccomp_profile(self, security_context):
        """
        Checks if a security context has a valid seccomp profile.

        Args:
            security_context (dict): The security context to check.

        Returns:
            bool: True if the seccomp profile is valid, False otherwise.
        """
        seccomp_profile = security_context.get("seccompProfile", {})
        seccomp_type = seccomp_profile.get("type")

        return seccomp_type in ["RuntimeDefault", "DockerDefault"]


@pytest.fixture
def seccomp_profile_not_set():
    return K8S_SEC_0016()


def test_detects_missing_seccomp_profile_in_pod(seccomp_profile_not_set):
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
    errors = seccomp_profile_not_set.check(parsed_content)
    assert len(errors) == 2


def test_detects_missing_seccomp_profile_in_deployment(seccomp_profile_not_set):
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
    errors = seccomp_profile_not_set.check(parsed_content)
    assert len(errors) == 2


def test_allows_valid_seccomp_profile_in_pod(seccomp_profile_not_set):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "securityContext": {
                    "seccompProfile": {
                        "type": "RuntimeDefault"
                    }
                },
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image",
                        "securityContext": {
                            "seccompProfile": {
                                "type": "RuntimeDefault"
                            }
                        }
                    }
                ]
            }
        }
    ]
    errors = seccomp_profile_not_set.check(parsed_content)
    assert len(errors) == 0


def test_allows_valid_seccomp_profile_in_deployment(seccomp_profile_not_set):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deployment", "lineNumber": 1},
            "spec": {
                "template": {
                    "spec": {
                        "securityContext": {
                            "seccompProfile": {
                                "type": "RuntimeDefault"
                            }
                        },
                        "containers": [
                            {
                                "name": "my-container",
                                "image": "my-image",
                                "securityContext": {
                                    "seccompProfile": {
                                        "type": "RuntimeDefault"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = seccomp_profile_not_set.check(parsed_content)
    assert len(errors) == 0
