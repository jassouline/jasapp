import os
import yaml


def is_valid_file(file_path):
    """
    Check if the provided path points to a valid file.

    Args:
        file_path (str): Path to the file.

    Returns:
        bool: True if the file exists and is a file, False otherwise.
    """
    return os.path.isfile(file_path)


def load_yaml(file_path):
    """
    Load and parse a YAML file.

    Args:
        file_path (str): Path to the YAML file.

    Returns:
        dict or list: Parsed YAML content as a dictionary or list.
    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the file is not a valid YAML file.
    """
    if not is_valid_file(file_path):
        raise FileNotFoundError(f"The file '{file_path}' does not exist or is not a valid file.")

    try:
        with open(file_path, "r") as file:
            return yaml.safe_load(file)
    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Error parsing YAML file '{file_path}': {e}")


def format_error(rule_name, message, severity, location=None):
    """
    Format an error message into a consistent structure.

    Args:
        rule_name (str): The name of the rule that generated the error.
        message (str): The error message.
        severity (str): The severity of the error ('info', 'warning', 'error').
        location (str or int, optional): The location of the error (line number or resource).

    Returns:
        dict: A formatted error dictionary.
    """
    error = {
        "rule": rule_name,
        "message": message,
        "severity": severity,
    }
    if location:
        error["location"] = location
    return error
