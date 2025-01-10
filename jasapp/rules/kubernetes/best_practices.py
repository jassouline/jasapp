from jasapp.rules.base_rule import BaseRule


class UseSpecificApiVersion(BaseRule):
    """
    Rule to ensure that Kubernetes resources use a specific API version.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            name="UseSpecificApiVersion",
            description="Ensure resources use a specific and supported 'apiVersion'. Avoid deprecated versions.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if resources specify a supported and specific API version.

        Args:
            resources (list): A list of dictionaries representing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with resource kind, message, and severity.
        """
        errors = []
        for resource in resources:
            api_version = resource.get("apiVersion", "")
            if not api_version or "alpha" in api_version or "beta" in api_version:
                errors.append({
                    "resource": resource.get("kind", "Unknown"),
                    "message": f"The resource of kind '{resource.get('kind', 'Unknown')}' is using an unstable or unspecified 'apiVersion'. Use a stable version instead.",
                    "severity": self.severity,
                })
        return errors


class SetResourceLimits(BaseRule):
    """
    Rule to ensure that containers specify resource limits and requests.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            name="SetResourceLimits",
            description="Ensure all containers specify resource limits and requests.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if containers within resources specify resource limits and requests.

        Args:
            resources (list): A list of dictionaries representing parsed Kubernetes resources.

        Returns:
            list: A list of errors found, each as a dictionary with resource kind, message, and severity.
        """
        errors = []
        for resource in resources:
            kind = resource.get("kind", "Unknown")
            spec = resource.get("spec", {})
            containers = spec.get("containers", [])

            for container in containers:
                if "resources" not in container:
                    errors.append({
                        "resource": kind,
                        "message": f"Container '{container.get('name', 'unknown')}' in '{kind}' is missing resource limits and requests.",
                        "severity": self.severity,
                    })
                else:
                    resources_spec = container.get("resources", {})
                    if not resources_spec.get("limits") or not resources_spec.get("requests"):
                        errors.append({
                            "resource": kind,
                            "message": f"Container '{container.get('name', 'unknown')}' in '{kind}' has incomplete resource specifications. Define both 'limits' and 'requests'.",
                            "severity": self.severity,
                        })
        return errors
