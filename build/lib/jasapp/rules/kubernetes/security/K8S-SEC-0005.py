import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_SEC_0005(BaseRule):
    """
    Rule to detect if Pods share the host's network namespace.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="HostNetworkSharingEnabled",
            name="K8S-SEC-0005",
            description="Containers should not share the host's network namespace.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if any Pod shares the host's network namespace.

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

                if spec.get("hostNetwork", False):
                    errors.append({
                        "line": resource["metadata"].get("lineNumber", "N/A"),
                        "message": f"{resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' allows sharing the host's network namespace.",
                        "severity": self.severity,
                        "kind": resource["kind"],
                    })

        return errors


@pytest.fixture
def host_network_sharing_enabled():
    return K8S_SEC_0005()


def test_pod_allows_host_network(host_network_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "hostNetwork": True,
                "containers": [
                    {
                        "name": "my-container",
                    }
                ]
            }
        }
    ]
    errors = host_network_sharing_enabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "allows sharing the host's network namespace" in errors[0]["message"]


def test_deployment_allows_host_network(host_network_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deployment", "lineNumber": 1},
            "spec": {"template": {"spec": {"hostNetwork": True,
                                           "containers": [
                                               {
                                                   "name": "my-container",
                                               }
                                           ]}}},
        }
    ]
    errors = host_network_sharing_enabled.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "allows sharing the host's network namespace" in errors[0]["message"]


def test_pod_disallows_host_network(host_network_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {"hostNetwork": False, "containers": [{"name": "my-container"}]},
        }
    ]
    errors = host_network_sharing_enabled.check(parsed_content)
    assert len(errors) == 0


def test_deployment_disallows_host_network(host_network_sharing_enabled):
    parsed_content = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deployment", "lineNumber": 1},
            "spec": {"template": {"spec": {"hostNetwork": False, "containers": [{"name": "my-container"}]}}},
        }
    ]
    errors = host_network_sharing_enabled.check(parsed_content)
    assert len(errors) == 0
