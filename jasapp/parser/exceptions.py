# jasapp/parser/exceptions.py
class ParsingException(Exception):
    """Base exception for parsing errors."""
    pass


class DockerfileParsingError(ParsingException):
    """Exception raised for errors in Dockerfile parsing."""
    pass


class KubernetesParsingError(ParsingException):
    """Exception raised for errors in Kubernetes manifest parsing."""
    pass
