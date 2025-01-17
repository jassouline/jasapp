import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_STX_0001(BaseRule):
    """
    Rule to detect if container images are not using a fixed tag.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="ImageTagNotFixed",
            name="K8S-STX-0001",
            description="Image tag is not set to a specific version. Avoid 'latest' or no tag.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if container images are using a fixed tag.

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
                    image = container.get("image", "")
                    if not image or not self.is_image_tag_fixed(image):
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not use a fixed image tag.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors

    def is_image_tag_fixed(self, image_string):
        """
        Checks if an image string has a fixed tag (not 'latest' and not empty).

        Args:
            image_string (str): The image string to check.

        Returns:
            bool: True if the image tag is fixed, False otherwise.
        """
        # Check if the image tag is 'latest' or empty
        return ":" in image_string and not image_string.endswith(":latest")


@pytest.fixture
def image_tag_not_fixed():
    return K8S_STX_0001()


def test_detects_latest_tag_in_pod(image_tag_not_fixed):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image:latest",
                    }
                ]
            }
        }
    ]
    errors = image_tag_not_fixed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not use a fixed image tag" in errors[0]["message"]


def test_detects_no_tag_in_deployment(image_tag_not_fixed):
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
                                "image": "my-image",
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = image_tag_not_fixed.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not use a fixed image tag" in errors[0]["message"]


def test_allows_fixed_tag_in_pod(image_tag_not_fixed):
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
    errors = image_tag_not_fixed.check(parsed_content)
    assert len(errors) == 0


def test_allows_fixed_tag_in_deployment(image_tag_not_fixed):
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
                                "image": "my-image:v1",
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = image_tag_not_fixed.check(parsed_content)
    assert len(errors) == 0
