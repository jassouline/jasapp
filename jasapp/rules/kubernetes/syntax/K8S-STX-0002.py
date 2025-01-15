import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_STX_0002(BaseRule):
    """
    Rule to detect if the `imagePullPolicy` is not set to `Always` for containers in Kubernetes resources.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="ImagePullPolicyNotAlways",
            name="K8S-STX-0002",
            description="`imagePullPolicy` is not set to `Always`.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if `imagePullPolicy` is set to `Always` for containers in Kubernetes resources.

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
                    image_pull_policy = container.get("imagePullPolicy")
                    if image_pull_policy != "Always":
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not have `imagePullPolicy` set to `Always`.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors


@pytest.fixture
def image_pull_policy_not_always():
    return K8S_STX_0002()


def test_detects_if_not_present_in_pod(image_pull_policy_not_always):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image:1.2.3",
                    }
                ]
            }
        }
    ]
    errors = image_pull_policy_not_always.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not have `imagePullPolicy` set to `Always`" in errors[0]["message"]


def test_detects_if_not_present_in_deployment(image_pull_policy_not_always):
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
                                "image": "my-image:1.2.3",
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = image_pull_policy_not_always.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not have `imagePullPolicy` set to `Always`" in errors[0]["message"]


def test_allows_image_pull_policy_always_in_pod(image_pull_policy_not_always):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image:1.2.3",
                        "imagePullPolicy": "Always"
                    }
                ]
            }
        }
    ]
    errors = image_pull_policy_not_always.check(parsed_content)
    assert len(errors) == 0


def test_allows_image_pull_policy_always_in_deployment(image_pull_policy_not_always):
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
                                "image": "my-image:1.2.3",
                                "imagePullPolicy": "Always"
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = image_pull_policy_not_always.check(parsed_content)
    assert len(errors) == 0


def test_detects_image_pull_policy_if_not_present_with_init_containers(image_pull_policy_not_always):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "initContainers": [
                    {
                        "name": "my-init-container",
                        "image": "my-init-image:1.0.0"
                    }
                ],
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image:1.2.3",
                        "imagePullPolicy": "Always"
                    }
                ]
            }
        }
    ]
    errors = image_pull_policy_not_always.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "Container 'my-init-container' in Pod 'my-pod' does not have `imagePullPolicy` set to `Always`" in errors[0]["message"]
