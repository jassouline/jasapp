
class Linter:
    """
    Core linting engine for applying rules to parsed configuration files.
    """

    def __init__(self, rules):
        """
        Initialize the linter with a set of rules.

        Args:
            rules (list): A list of rule instances to apply.
        """
        self.rules = rules

    def run(self, parsed_content):
        """
        Run the linter by applying all rules to the parsed content.

        Args:
            parsed_content (list): Parsed content from a configuration file
                                   (e.g., Dockerfile instructions or Kubernetes resources).

        Returns:
            list: A list of errors found, where each error is a dictionary containing:
                  - 'rule': The name of the violated rule.
                  - 'message': The error message from the rule.
                  - 'severity': The severity of the issue.
                  - 'line' or 'resource': The location of the issue (line for Dockerfile,
                                           resource kind for Kubernetes).
        """
        errors = []

        for rule in self.rules:
            try:
                rule_errors = rule.check(parsed_content)

                for error in rule_errors:
                    errors.append({
                        "rule": rule.name,
                        "message": error["message"],
                        "severity": error["severity"],
                        "doc_link": error["doc_link"],
                        **({"line": error["line"]} if "line" in error else {"resource": error["resource"]}),
                    })
            except Exception as e:
                print(f"Error in rule {rule.name}: {e}")
                errors.append({
                    "rule": rule.name,
                    "message": f"Unexpected error while running rule '{rule.name}': {e}",
                    "severity": "error",
                })

        return errors
