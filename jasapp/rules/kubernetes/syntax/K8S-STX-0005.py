import pytest
from jasapp.rules.base_rule import BaseRule


class K8S_STX_0005(BaseRule):
    """
    Rule to detect if container images are not using digests for versioning.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            friendly_name="ImageTagIsDigest",
            name="K8S-STX-0004",
            description="Image tag should be a digest (sha256) for immutability.",
            severity="info",
        )

    def check(self, resources):
        """
        Checks if container images are using digests for versioning.

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
                    if not self.is_image_using_digest(image):
                        errors.append({
                            "line": resource["metadata"].get("lineNumber", "N/A"),
                            "message": f"Container '{container['name']}' in {resource['kind']} '{resource['metadata'].get('name', 'Unknown')}' does not use a digest for the image tag.",
                            "severity": self.severity,
                            "kind": resource["kind"],
                        })

        return errors

    def is_image_using_digest(self, image_string):
        """
        Checks if an image string is using a digest.

        Args:
            image_string (str): The image string to check.

        Returns:
            bool: True if the image is using a digest, False otherwise.
        """
        if not image_string:
            return False

        return "@sha256:" in image_string


@pytest.fixture
def image_tag_is_digest():
    return K8S_STX_0005()


def test_detects_missing_digest_in_pod(image_tag_is_digest):
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
    errors = image_tag_is_digest.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not use a digest for the image tag" in errors[0]["message"]


def test_detects_missing_digest_in_deployment(image_tag_is_digest):
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
                                "image": "my-image:latest",
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = image_tag_is_digest.check(parsed_content)
    assert len(errors) == 1
    assert errors[0]["line"] == 1
    assert "does not use a digest for the image tag" in errors[0]["message"]


def test_allows_digest_in_pod(image_tag_is_digest):
    parsed_content = [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod", "lineNumber": 1},
            "spec": {
                "containers": [
                    {
                        "name": "my-container",
                        "image": "my-image@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    }
                ]
            }
        }
    ]
    errors = image_tag_is_digest.check(parsed_content)
    assert len(errors) == 0


def test_allows_digest_in_deployment(image_tag_is_digest):
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
                                "image": "my-image@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                            }
                        ]
                    }
                }
            }
        }
    ]
    errors = image_tag_is_digest.check(parsed_content)
    assert len(errors) == 0
