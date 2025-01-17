import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0028(BaseRule):
    """
    Rule to detect if Tiller (Helm V2) deployment is accessible from within the cluster.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="TillerAccessible",
            name="K8S-SEC-0028",
            description="Tiller (Helm V2) deployment is accessible from within the cluster.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if Tiller deployment is accessible from within the cluster based on its configuration.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] == "Deployment" and resource["metadata"].get("name") == "tiller-deploy":
                containers = resource["spec"].get("template", {}).get("spec", {}).get("containers", [])
                for container in containers:
                    if container["name"] == "tiller":
                        if self.is_tiller_accessible(container):
                            errors.append({
                                "line": resource["metadata"].get("lineNumber", "N/A"),
                                "message": f"Tiller deployment is accessible from within the cluster in Deployment '{resource['metadata'].get('name', 'Unknown')}'.",
                                "severity": self.severity,
                                "kind": resource["kind"],
                            })

        return errors

    def is_tiller_accessible(self, container):
        """
        Checks if the Tiller container is accessible from within the cluster.

        Args:
            container (dict): The container specification.

        Returns:
            bool: True if Tiller is accessible, False otherwise.
        """
        # Check if Tiller is configured to listen on localhost only
        args = container.get("args", [])
        for arg in args:
            if arg.startswith("--listen"):
                if "localhost:44134" not in arg:
                    return True
                else:
                    return False

        # Check if Tiller port (44134) is exposed
        for port in container.get("ports", []):
            if port.get("containerPort") == 44134 and port.get("protocol", "TCP") == "TCP":
                return True

        return False


@pytest.fixture
def tiller_accessible():
    return K8S_SEC_0028()


def test_detects_tiller_accessible_via_port(tiller_accessible):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "tiller-deploy", "lineNumber": 1},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "tiller",
                                "image": "gcr.io/kubernetes-helm/tiller:v2.16.9",
                                "ports": [
                                    {
                                        "containerPort": 44134,
                                        "protocol": "TCP"
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = tiller_accessible.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Tiller deployment is accessible" in errors[0]["message"]


def test_detects_tiller_accessible_via_no_port_restriction(tiller_accessible):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "tiller-deploy", "lineNumber": 1},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "tiller",
                                "image": "gcr.io/kubernetes-helm/tiller:v2.16.9",
                                "args": [
                                    "--listen=:44134"
                                ]
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = tiller_accessible.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Tiller deployment is accessible" in errors[0]["message"]


def test_allows_tiller_listening_on_localhost(tiller_accessible):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "tiller-deploy", "lineNumber": 1},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "tiller",
                                "image": "gcr.io/kubernetes-helm/tiller:v2.16.9",
                                "args": [
                                    "--listen=localhost:44134"
                                ]
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = tiller_accessible.check(parsed_content)
    assert len(errors) == 0
