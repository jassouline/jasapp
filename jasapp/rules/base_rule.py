class BaseRule:
    """
    Base class for linting rules.

    Each rule is expected to inherit from this class and implement the `check` method.
    """
    rule_type = "generic"  # Default to generic. Can be "dockerfile" or "kubernetes".

    def __init__(self, name, description, severity="warning", friendly_name=None, hadolint=None, doc_link=None):
        """
        Initialize a linting rule.

        Args:
            name (str): The unique name of the rule.
            description (str): A brief description of what the rule checks for.
            severity (str): The severity of the rule ('info', 'warning', 'error').
        """
        self.name = name
        self.description = description
        self.severity = severity
        self.friendly_name = friendly_name
        self.hadolint = hadolint

    def check(self, instructions):
        """
        Abstract method to be implemented by specific rules.

        Args:
            instructions (list): A list of instructions or resources to be analyzed.

        Returns:
            list: A list of errors found, where each error is a dictionary containing:
                  - 'line': The line number of the issue (if applicable).
                  - 'message': A detailed error message.
                  - 'severity': The severity of the issue.
        """
        raise NotImplementedError("The `check` method must be implemented by subclasses.")
