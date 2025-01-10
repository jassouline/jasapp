from jasapp.rules.base_rule import BaseRule


class AvoidPrivilegedContainers(BaseRule):
    """
    Rule to ensure that containers are not running in privileged mode.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            name="AvoidPrivilegedContainers",
            description="Ensure containers do not run in privileged mode.",
            severity="error",
        )

    def check(self, resources):
        """
        Checks if any container is running in privileged mode.

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
                security_context = container.get("securityContext", {})
                if security_context.get("privileged", False):
                    errors.append({
                        "resource": kind,
                        "message": f"Container '{container.get('name', 'unknown')}' in '{kind}' is running in privileged mode. Avoid this for security reasons.",
                        "severity": self.severity,
                    })
        return errors


class EnsureReadOnlyRootFilesystem(BaseRule):
    """
    Rule to ensure that containers use a read-only root filesystem.
    """
    rule_type = "kubernetes"

    def __init__(self):
        super().__init__(
            name="EnsureReadOnlyRootFilesystem",
            description="Ensure containers use a read-only root filesystem.",
            severity="warning",
        )

    def check(self, resources):
        """
        Checks if any container has a writable root filesystem.

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
                security_context = container.get("securityContext", {})
                if not security_context.get("readOnlyRootFilesystem", False):
                    errors.append({
                        "resource": kind,
                        "message": f"Container '{container.get('name', 'unknown')}' in '{kind}' does not use a read-only root filesystem. Enable this for better security.",
                        "severity": self.severity,
                    })
        return errors
