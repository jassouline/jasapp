import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0018(BaseRule):
    """
    Rule to detect if seccomp profile is not set to `RuntimeDefault` or `DockerDefault` in Pods and containers.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="SeccompProfileNotDefault",
            name="K8S-SEC-0018",
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
                pod_metadata = spec.get("template", {}).get("metadata", {}) if resource["kind"] != "Pod" else resource["metadata"]
                pod_security_context = spec.get("securityContext", {})

                # Check container-level security context
                containers = spec.get("containers", [])
                init_containers = spec.get("initContainers", [])

                container_errors = []
                for container in containers + init_containers:
                    security_context = container.get("securityContext", {})
                    if not self.is_valid_seccomp_profile(pod_metadata, security_context, container['name']):
                        container_errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not have a valid seccomp profile.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

                # Only add a Pod-level error if no container has a valid profile
                if not self.is_valid_seccomp_profile(pod_metadata, pod_security_context) and len(container_errors) == len(containers) + len(init_containers):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"Pod '{resource['metadata'].get('name', 'Unknown')}' in {resource['kind']} does not have a valid seccomp profile.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

                errors.extend(container_errors)

        return errors

    def is_valid_seccomp_profile(self, metadata, security_context, container_name=None):
        """
        Checks if a security context has a valid seccomp profile.

        Args:
            metadata(dict): The metadata of the resource (pod or template).
            security_context (dict): The security context to check.
            container_name (str): The container name.

        Returns:
            bool: True if the seccomp profile is valid, False otherwise.
        """

        # For older Kubernetes versions, check for annotations
        annotations = metadata.get("annotations", {})

        # Check for seccomp profile at the Pod level
        pod_seccomp_annotation = annotations.get("seccomp.security.alpha.kubernetes.io/pod")
        if pod_seccomp_annotation in ["runtime/default", "docker/default"]:
            return True

        # If a container name is provided, check for container-specific annotations
        if container_name:
            container_seccomp_annotation = annotations.get(f"container.seccomp.security.alpha.kubernetes.io/{container_name}")
            if container_seccomp_annotation in ["runtime/default", "docker/default"]:
                return True
            elif container_seccomp_annotation is not None:
                return False

        # Check for seccomp profile in securityContext (for Kubernetes >= 1.19)
        seccomp_profile = security_context.get("seccompProfile", {})
        seccomp_type = seccomp_profile.get("type")
        return seccomp_type in ["RuntimeDefault", "DockerDefault"]


@pytest.fixture
def seccomp_profile_not_set():
    return K8S_SEC_0018()


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
    assert errors[0]["line"] == 1
    assert "does not have a valid seccomp profile" in errors[0]["message"]


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
    assert errors[0]["line"] == 1
    assert "does not have a valid seccomp profile" in errors[0]["message"]


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


def test_allows_valid_seccomp_annotation_in_pod(seccomp_profile_not_set):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod", "lineNumber": 1,
                "annotations": {
                    "seccomp.security.alpha.kubernetes.io/pod": "docker/default"
                }
            },
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
    errors = seccomp_profile_not_set.check(parsed_content)
    assert len(errors) == 0


def test_allows_valid_seccomp_container_annotation_in_pod(seccomp_profile_not_set):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod", "lineNumber": 1,
                "annotations": {
                    "container.seccomp.security.alpha.kubernetes.io/my-container": "docker/default"
                    }
            },
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
                    "metadata": {
                        "annotations": {
                            "seccomp.security.alpha.kubernetes.io/pod": "runtime/default"
                        }
                    },
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
