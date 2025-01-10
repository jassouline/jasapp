from jasapp.rules.base_rule import BaseRule


class RequireMetadata(BaseRule):
    """
    Rule to ensure that all Kubernetes resources include metadata fields.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            name="RequireMetadata",
            description="Ensure all Kubernetes resources include 'metadata' fields.",
            severity="error",
        )

    def check(self, resources):
        """
        Checks if each Kubernetes resource contains a 'metadata' field.

        Args:
            resources (list): A list of dictionaries representing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with resource kind, message, and severity.
        """
        errors = []
        for resource in resources:
            if "metadata" not in resource or not resource["metadata"]:
                errors.append({
                    "resource": resource.get("kind", "Unknown"),
                    "message": f"The resource of kind '{resource.get('kind', 'Unknown')}' is missing 'metadata'.",
                    "severity": self.severity,
                })
        return errors


class RequireApiVersion(BaseRule):
    """
    Rule to ensure that all Kubernetes resources specify 'apiVersion'.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            name="RequireApiVersion",
            description="Ensure all Kubernetes resources specify an 'apiVersion'.",
            severity="error",
        )

    def check(self, resources):
        """
        Checks if each Kubernetes resource contains an 'apiVersion' field.

        Args:
            resources (list): A list of dictionaries representing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with resource kind, message, and severity.
        """
        errors = []
        for resource in resources:
            if "apiVersion" not in resource or not resource["apiVersion"]:
                errors.append({
                    "resource": resource.get("kind", "Unknown"),
                    "message": f"The resource of kind '{resource.get('kind', 'Unknown')}' is missing 'apiVersion'.",
                    "severity": self.severity,
                })
        return errors
