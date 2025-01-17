import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0019(BaseRule):
    """
    Rule to detect if the Kubernetes dashboard is deployed.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="KubernetesDashboardDeployed",
            name="K8S-SEC-0019",
            description="Kubernetes dashboard is deployed.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if the Kubernetes dashboard is deployed.

        Args:
            resources (list): A list of dictionaries containing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with line, message, severity, and kind.
        """
        errors = []

        for resource in resources:
            if resource["kind"] == "Pod":
                if self.is_kubernetes_dashboard_pod(resource):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"Kubernetes dashboard is deployed in Pod '{resource['metadata'].get('name', 'Unknown')}'.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

        return errors

    def is_kubernetes_dashboard_pod(self, resource):
        """
        Checks if a Pod resource is likely to be a Kubernetes dashboard.

        Args:
            resource (dict): The parsed Pod resource.

        Returns:
            bool: True if it's likely a Kubernetes dashboard Pod, False otherwise.
        """
        labels = resource["metadata"].get("labels", {})
        if "kubernetes-dashboard" in labels.get("app", "").lower():
            return True
        if "kubernetes-dashboard" in labels.get("k8s-app", "").lower():
            return True

        containers = resource["spec"].get("containers", [])
        for container in containers:
            image = container.get("image", "").lower()
            if "kubernetes-dashboard" in image or "kubernetesui" in image:
                return True

        return False


@pytest.fixture
def kubernetes_dashboard_deployed():
    return K8S_SEC_0019()


def test_detects_dashboard_pod_by_label_app(kubernetes_dashboard_deployed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "kubernetes-dashboard-pod",
                "labels": {
                    "app": "kubernetes-dashboard"
                },
                "lineNumber": 1
            },
            "spec": {
                "containers": [
                    {
                        "name": "dashboard-container",
                        "image": "some-image"
                    }
                ]
            }
        }
    ]
    errors = kubernetes_dashboard_deployed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Kubernetes dashboard is deployed" in errors[0]["message"]


def test_detects_dashboard_pod_by_label_k8s_app(kubernetes_dashboard_deployed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "kubernetes-dashboard-pod",
                "labels": {
                    "k8s-app": "kubernetes-dashboard"
                },
                "lineNumber": 1
            },
            "spec": {
                "containers": [
                    {
                        "name": "dashboard-container",
                        "image": "some-image"
                    }
                ]
            }
        }
    ]
    errors = kubernetes_dashboard_deployed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Kubernetes dashboard is deployed" in errors[0]["message"]


def test_detects_dashboard_pod_by_image_name(kubernetes_dashboard_deployed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "dashboard-pod",
                "lineNumber": 1
            },
            "spec": {
                "containers": [
                    {
                        "name": "dashboard-container",
                        "image": "kubernetesui/dashboard"
                    }
                ]
            }
        }
    ]
    errors = kubernetes_dashboard_deployed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Kubernetes dashboard is deployed" in errors[0]["message"]


def test_allows_pod_without_dashboard(kubernetes_dashboard_deployed):
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
    errors = kubernetes_dashboard_deployed.check(parsed_content)
    assert len(errors) == 0
