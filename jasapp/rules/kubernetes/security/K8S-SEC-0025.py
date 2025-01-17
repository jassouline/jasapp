import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0025(BaseRule):
    """
    Rule to detect if containers are not configured to run with a high UID.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="RunAsHighUID",
            name="K8S-SEC-0025",
            description="Containers should be configured to run with a high UID (>= 10000).",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if containers are configured to run with a high UID.

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
                    run_as_user = security_context.get("runAsUser")
                    if run_as_user is None or run_as_user < 10000:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is not configured to run with a high UID (>= 10000).",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def run_as_high_uid():
    return K8S_SEC_0025()


def test_detects_low_uid_in_pod(run_as_high_uid):
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
                            "runAsUser": 1000
                        }
                    }
                ]
            }
        }
    ]
    errors = run_as_high_uid.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is not configured to run with a high UID" in errors[0]["message"]


def test_detects_missing_run_as_user_in_deployment(run_as_high_uid):
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
                                "image": "my-image"
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = run_as_high_uid.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is not configured to run with a high UID" in errors[0]["message"]


def test_allows_high_uid_in_pod(run_as_high_uid):
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
                            "runAsUser": 10000
                        }
                    }
                ]
            }
        }
    ]
    errors = run_as_high_uid.check(parsed_content)
    assert len(errors) == 0


def test_detects_low_uid_in_init_container(run_as_high_uid):
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
                            "runAsUser": 1000
                        }
                    }
                ],
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image",
                        "securityContext": {
                            "runAsUser": 10000
                        }
                    }
                ]
            }
        }
    ]
    errors = run_as_high_uid.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-init-container' in Pod 'my-pod' is not configured to run with a high UID" in errors[0]["message"]
