import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0012(BaseRule):
    """
    Rule to detect if containers are using hostPort.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="HostPortUsed",
            name="K8S-SEC-0010",
            description="Containers should not use hostPort.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if containers are using hostPort.

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
                    for port in container.get("ports", []):
                        if "hostPort" in port:
                            errors.append({
                                "line": resource["metadata"].get("lineNumber", "N/A"),
                                "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is using hostPort.",
                                "severity": self.severity,
                                "kind": resource["kind"],
                            })

        return errors


@pytest.fixture
def host_port_used():
    return K8S_SEC_0012()


def test_detects_host_port_in_pod(host_port_used):
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
                        "ports": [
                            {
                                "containerPort": 80,
                                "hostPort": 8080
                            }
                        ]
                    }
                ]
            }
        }
    ]
    errors = host_port_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is using hostPort" in errors[0]["message"]


def test_detects_host_port_in_deployment(host_port_used):
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
                                "ports": [
                                    {
                                        "containerPort": 80,
                                        "hostPort": 8080
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = host_port_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is using hostPort" in errors[0]["message"]


def test_detects_host_port_in_init_container(host_port_used):
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
                        "ports": [
                            {
                                "containerPort": 80,
                                "hostPort": 8080
                            }
                        ]
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
    errors = host_port_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is using hostPort" in errors[0]["message"]


def test_allows_pod_without_host_port(host_port_used):
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
                        "ports": [
                            {
                                "containerPort": 80
                            }
                        ]
                    }
                ]
            }
        }
    ]
    errors = host_port_used.check(parsed_content)
    assert len(errors) == 0
