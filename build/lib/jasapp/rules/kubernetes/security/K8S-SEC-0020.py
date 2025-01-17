import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0020(BaseRule):
    """
    Rule to detect if Tiller (Helm V2) is deployed in the cluster.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="TillerDeployed",
            name="K8S-SEC-0020",
            description="Tiller (Helm V2) is deployed, which has known security risks.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if Tiller is deployed based on common labels and image names.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] == "Pod":
                if self.is_tiller_pod(resource):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"Tiller (Helm V2) is deployed in Pod '{resource['metadata'].get('name', 'Unknown')}'. Consider upgrading to Helm V3.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

        return errors

    def is_tiller_pod(self, resource):
        """
        Checks if a Pod resource is likely to be a Tiller deployment.

        Args:
            resource (dict): The parsed Pod resource.

        Returns:
            bool: True if it's likely a Tiller Pod, False otherwise.
        """
        labels = resource["metadata"].get("labels", {})
        if "app" in labels and labels["app"].lower() == "helm" and "name" in labels and labels["name"].lower() == "tiller":
            return True

        containers = resource["spec"].get("containers", [])
        for container in containers:
            image = container.get("image", "").lower()
            if "tiller" in image:
                return True

        return False


@pytest.fixture
def tiller_deployed():
    return K8S_SEC_0020()


def test_detects_tiller_pod_by_labels(tiller_deployed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "tiller-pod",
                "labels": {
                    "app": "helm",
                    "name": "tiller"
                },
                "lineNumber": 1
            },
            "spec": {
                "containers": [
                    {
                        "name": "tiller-container",
                        "image": "some-image"
                    }
                ]
            }
        }
    ]
    errors = tiller_deployed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Tiller (Helm V2) is deployed" in errors[0]["message"]


def test_detects_tiller_pod_by_image_name(tiller_deployed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "tiller-pod",
                "lineNumber": 1
            },
            "spec": {
                "containers": [
                    {
                        "name": "tiller-container",
                        "image": "gcr.io/kubernetes-helm/tiller:v2.16.0"
                    }
                ]
            }
        }
    ]
    errors = tiller_deployed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Tiller (Helm V2) is deployed" in errors[0]["message"]


def test_allows_pod_without_tiller(tiller_deployed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod",
                "lineNumber": 1
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
    errors = tiller_deployed.check(parsed_content)
    assert len(errors) == 0
