class Scorer:
    """
    Scoring system to evaluate the quality of configuration files based on linting results.
    """

    def __init__(self):
        """
        Initialize the Scorer with weights for severity levels.
        """
        self.weights = {
            "ignore": 0,
            "info": 1,
            "warning": 5,
            "error": 10,
        }

    def calculate(self, errors, total_rules):
        """
        Calculate the quality score for a file.

        Args:
            errors (list): A list of errors from the linter.
            total_rules (int): The total number of rules applied.

        Returns:
            int: The quality score (0-100).
        """
        if not total_rules:
            return 100  # Perfect score if no rules were applied

        # Calculate total penalty
        total_penalty = sum(self.weights.get(error["severity"], 0) for error in errors)

        # Define a base penalty threshold to prevent overly harsh scoring
        # max_penalty = total_rules * self.weights["error"]

        # Calculate the score as a percentage
        score = max(0, 100 - total_penalty)
        return score
