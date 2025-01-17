import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0029(BaseRule):
    """
    Rule to detect if the Tiller (Helm V2) service is not deleted from the cluster.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="TillerServiceNotDeleted",
            name="K8S-SEC-0029",
            description="Tiller (Helm V2) service should be deleted from the cluster.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if the Tiller service is present in the cluster.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] == "Service" and resource["metadata"].get("name") == "tiller-deploy":
                errors.append({
                    "line": resource["metadata"].get("lineNumber", "N/A"),
                    "message": f"Tiller (Helm V2) service '{resource['metadata'].get('name', 'Unknown')}' found. It should be deleted.",
                    "severity": self.severity,
                    "kind": resource["kind"],
                })

        return errors


@pytest.fixture
def tiller_service_not_deleted():
    return K8S_SEC_0029()


def test_detects_tiller_service(tiller_service_not_deleted):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "tiller-deploy", "namespace": "kube-system", "lineNumber": 1},
            "spec": {
                "ports": [
                    {
                        "name": "tiller",
                        "port": 44134,
                        "protocol": "TCP",
                        "targetPort": "tiller"
                    }
                ],
                "selector": {
                    "app": "helm",
                    "name": "tiller"
                },
                "type": "ClusterIP"
            }
        }
    ]
    errors = tiller_service_not_deleted.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Tiller (Helm V2) service 'tiller-deploy' found" in errors[0]["message"]


def test_allows_no_tiller_service(tiller_service_not_deleted):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-service", "lineNumber": 1},
            "spec": {
                "ports": [
                    {
                        "name": "http",
                        "port": 80,
                        "protocol": "TCP",
                        "targetPort": "http"
                    }
                ],
                "selector": {
                    "app": "my-app"
                },
                "type": "ClusterIP"
            }
        }
    ]
    errors = tiller_service_not_deleted.check(parsed_content)
    assert len(errors) == 0
