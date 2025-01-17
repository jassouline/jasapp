import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0026(BaseRule):
    """
    Rule to detect if the default service account is actively used.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="DefaultServiceAccountUsed",
            name="K8S-SEC-0026",
            description="The default service account should not be actively used.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if the default service account is actively used.

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

                service_account_name = spec.get("serviceAccountName", "default")

                if service_account_name == "default":
                    errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"{resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is using the default service account. Create a dedicated service account.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

            elif resource["kind"] in ["RoleBinding", "ClusterRoleBinding"]:
                subjects = resource.get("subjects", [])
                for subject in subjects:
                    if subject.get("kind") == "ServiceAccount" and subject.get("name") == "default":
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"{resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' is bound to the default service account.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })
            elif resource["kind"] == "ServiceAccount":
                if resource["metadata"].get("name") == "default":
                    # Check if automountServiceAccountToken is explicitly set to false
                    automount_token = resource.get("automountServiceAccountToken")
                    if automount_token is None or automount_token:
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": "Default service account should have automountServiceAccountToken set to false.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def default_service_account_used():
    return K8S_SEC_0026()


def test_detects_default_service_account_in_pod(default_service_account_used):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "serviceAccountName": "default",
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image"
                    }
                ]
            }
        }
    ]
    errors = default_service_account_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is using the default service account" in errors[0]["message"]


def test_detects_default_service_account_implicit_in_pod(default_service_account_used):
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
    errors = default_service_account_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is using the default service account" in errors[0]["message"]


def test_detects_default_service_account_in_role_binding(default_service_account_used):
    parsed_content = [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "my-role-binding", "lineNumber": 1},
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": "default",
                    "namespace": "my-namespace"
                }
            ],
            "roleRef": {
                "kind": "Role",
                "name": "my-role",
                "apiGroup": "rbac.authorization.k8s.io"
            }
        }
    ]
    errors = default_service_account_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is bound to the default service account" in errors[0]["message"]


def test_detects_default_service_account_in_cluster_role_binding(default_service_account_used):
    parsed_content = [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "my-cluster-role-binding", "lineNumber": 1},
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": "default",
                    "namespace": "my-namespace"
                }
            ],
            "roleRef": {
                "kind": "ClusterRole",
                "name": "my-cluster-role",
                "apiGroup": "rbac.authorization.k8s.io"
            }
        }
    ]
    errors = default_service_account_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "is bound to the default service account" in errors[0]["message"]


def test_detects_default_service_account_without_token_mounted(default_service_account_used):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "default", "lineNumber": 1},
            "automountServiceAccountToken": False
        }
    ]
    errors = default_service_account_used.check(parsed_content)
    assert len(errors) == 0


def test_detects_default_service_account_with_token_mounted(default_service_account_used):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "default", "lineNumber": 1},
            "automountServiceAccountToken": True
        }
    ]
    errors = default_service_account_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Default service account should have" in errors[0]["message"]


def test_detects_default_service_account_with_token_mounted_implicit(default_service_account_used):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "default", "lineNumber": 1}
        }
    ]
    errors = default_service_account_used.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Default service account should have" in errors[0]["message"]


def test_allows_non_default_service_account(default_service_account_used):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "serviceAccountName": "my-service-account",
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image"
                    }
                ]
            }
        }
    ]
    errors = default_service_account_used.check(parsed_content)
    assert len(errors) == 0
