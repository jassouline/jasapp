import yaml


class KubernetesParser:
    """
    Parses Kubernetes manifests and extracts key resources and their metadata.
    """

    def __init__(self, file_path):
        """
        Initialize the parser with the path to the Kubernetes manifest.

        Args:
            file_path (str): Path to the Kubernetes YAML manifest.
        """
        self.file_path = file_path

    def parse(self):
        """
        Parses the Kubernetes manifest and returns a list of resources.

        Returns:
            list: A list of dictionaries, each containing the resource kind,
                  metadata (e.g., name, namespace), and spec.
        Raises:
            FileNotFoundError: If the specified file does not exist.
            yaml.YAMLError: If the YAML file is invalid.
            Exception: For other unexpected parsing errors.
        """
        resources = []
        try:
            with open(self.file_path, "r") as file:
                documents = yaml.safe_load_all(file)
                for document in documents:
                    if document:
                        resource = {
                            "kind": document.get("kind", "Unknown"),
                            "metadata": document.get("metadata", {}),
                            "spec": document.get("spec", {}),
                        }
                        resources.append(resource)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {self.file_path}")
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Invalid YAML file: {e}")
        except Exception as e:
            raise Exception(f"An error occurred while parsing the file: {e}")
        return resources

    def parse_from_string(self, content):
        """
        Parses a Kubernetes manifest from a string and returns a list of resources.

        Args:
            content (str): The content of the Kubernetes manifest as a string.

        Returns:
            list: A list of dictionaries, each containing the resource kind,
                  metadata (e.g., name, namespace), and spec.
        """
        resources = []
        documents = yaml.safe_load_all(content)
        for document in documents:
            if document:
                resource = {
                    "kind": document.get("kind", "Unknown"),
                    "metadata": document.get("metadata", {}),
                    "spec": document.get("spec", {}),
                }
                resources.append(resource)
        return resources
