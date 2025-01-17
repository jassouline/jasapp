import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0013(BaseRule):
    """
    Rule to detect if the Docker socket (`/var/run/docker.sock`) is mounted in a container.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="DockerSocketMounted",
            name="K8S-SEC-0013",
            description="Containers should not mount the Docker socket.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if the Docker socket is mounted in containers.

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

                volumes = spec.get("volumes", [])
                for volume in volumes:
                    host_path = volume.get("hostPath", {}).get("path", "")
                    if host_path == "/var/run/docker.sock":
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"{resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' mounts the Docker socket.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def docker_socket_mounted():
    return K8S_SEC_0013()


def test_pod_mounts_docker_socket(docker_socket_mounted):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "volumes": [
                    {
                        "name": "docker-socket",
                        "hostPath": {
                            "path": "/var/run/docker.sock"
                        }
                    }
                ],
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image"
                    }
                ]
            }
        }
    ]
    errors = docker_socket_mounted.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "mounts the Docker socket" in errors[0]["message"]


def test_deployment_mounts_docker_socket(docker_socket_mounted):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deployment", "lineNumber": 1},
            "spec": {
                "template": {
                    "spec": {
                        "volumes": [
                            {
                                "name": "docker-socket",
                                "hostPath": {
                                    "path": "/var/run/docker.sock"
                                }
                            }
                        ],
                        "containers": [
                            {
                                "name": "my-container",
                                "image": "my-image"
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = docker_socket_mounted.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "mounts the Docker socket" in errors[0]["message"]


def test_pod_does_not_mount_docker_socket(docker_socket_mounted):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "volumes": [
                    {
                        "name": "my-volume",
                        "hostPath": {
                            "path": "/tmp"
                        }
                    }
                ],
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image"
                    }
                ]
            }
        }
    ]
    errors = docker_socket_mounted.check(parsed_content)
    assert len(errors) == 0
