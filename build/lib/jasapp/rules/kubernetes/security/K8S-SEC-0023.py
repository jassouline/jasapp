import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0023(BaseRule):
    """
    Rule to detect if service account tokens are not explicitly mounted when necessary.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="ServiceAccountTokenMounting",
            name="K8S-SEC-0023",
            description="Service account tokens should not be mounted unless explicitly set to false.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if service account tokens are mounted when `automountServiceAccountToken` is not explicitly set to false.

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

                # Check if automountServiceAccountToken is explicitly set to false
                if spec.get("automountServiceAccountToken") is None:
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"{resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not set `automountServiceAccountToken` to `false`.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

        return errors


@pytest.fixture
def service_account_token_not_mounted():
    return K8S_SEC_0023()


def test_detects_implicit_service_account_token_mount_in_pod(service_account_token_not_mounted):
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
    errors = service_account_token_not_mounted.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not set `automountServiceAccountToken` to `false`" in errors[0]["message"]


def test_detects_implicit_service_account_token_mount_in_deployment(service_account_token_not_mounted):
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
    errors = service_account_token_not_mounted.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not set `automountServiceAccountToken` to `false`" in errors[0]["message"]


def test_allows_explicitly_disabled_service_account_token_mount(service_account_token_not_mounted):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "automountServiceAccountToken": False,
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image"
                    }
                ]
            }
        }
    ]
    errors = service_account_token_not_mounted.check(parsed_content)
    assert len(errors) == 0
