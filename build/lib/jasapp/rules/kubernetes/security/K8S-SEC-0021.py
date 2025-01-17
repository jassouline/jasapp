import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0021(BaseRule):
    """
    Rule to detect if secrets are used as environment variables in containers.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="SecretsAsEnvironmentVariables",
            name="K8S-SEC-0021",
            description="Secrets should not be used as environment variables.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if secrets are used as environment variables in containers.

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
                    # Check for environment variables using secrets with valueFrom
                    for env in container.get("env", []):
                        if env.get("valueFrom", {}).get("secretKeyRef"):
                            errors.append({
                                "line": resource["metadata"].get("lineNumber", "N/A"),
                                "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' uses secret as environment variable via valueFrom.",
                                "severity": self.severity,
                                "kind": resource["kind"],
                            })

                    # Check for environment variables using secrets with envFrom
                    if container.get("envFrom"):
                        for env_from in container.get("envFrom", []):
                            if env_from.get("secretRef"):
                                errors.append({
                                    "line": resource["metadata"].get("lineNumber", "N/A"),
                                    "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' uses secret as environment variable via envFrom.",
                                    "severity": self.severity,
                                    "kind": resource["kind"],
                                })

        return errors


@pytest.fixture
def secrets_as_env_vars():
    return K8S_SEC_0021()


def test_detects_secret_as_env_var_value_from(secrets_as_env_vars):
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
                        "env": [
                            {
                                "name": "MY_SECRET",
                                "valueFrom": {
                                    "secretKeyRef": {
                                        "name": "my-secret",
                                        "key": "my-secret-key"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }
    ]
    errors = secrets_as_env_vars.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "uses secret as environment variable via valueFrom" in errors[0]["message"]


def test_detects_secret_as_env_var_env_from(secrets_as_env_vars):
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
                        "envFrom": [
                            {
                                "secretRef": {
                                    "name": "my-secret"
                                }
                            }
                        ]
                    }
                ]
            }
        }
    ]
    errors = secrets_as_env_vars.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "uses secret as environment variable via envFrom" in errors[0]["message"]


def test_allows_non_secret_env_vars(secrets_as_env_vars):
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
                        "env": [
                            {
                                "name": "MY_VAR",
                                "value": "my-value"
                            }
                        ]
                    }
                ]
            }
        }
    ]
    errors = secrets_as_env_vars.check(parsed_content)
    assert len(errors) == 0
