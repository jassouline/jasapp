import os
import importlib
import inspect


def extract_rule_data(rules_dir):
    """
    Extracts rule information (name, description, severity) from Python files in the specified directory.

    Args:
        rules_dir (str): The directory containing the rule files.

    Returns:
        list: A list of dictionaries, where each dictionary represents a rule and contains its name, description, and severity.
    """
    rule_data = []
    for filename in os.listdir(rules_dir):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = filename[:-3]  # Remove .py extension
            try:
                # Construct the module path for dynamic importing
                module_path = f"jasapp.rules.dockerfile.{os.path.basename(rules_dir)}.{module_name}"
                module = importlib.import_module(module_path)

                # Iterate over classes within each module
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and hasattr(obj, 'rule_type') and obj.rule_type == "dockerfile":
                        # Assuming the class name matches the rule name (e.g., STX0001)
                        rule_instance = obj()
                        rule_data.append({
                            "name": rule_instance.name,
                            "description": rule_instance.description,
                            "severity": rule_instance.severity
                        })
            except (ImportError, AttributeError) as e:
                print(f"Error importing or processing {filename}: {e}")

    return rule_data


def generate_markdown_table(rule_data, section):
    """
    Generates a Markdown table from the extracted rule data.

    Args:
        rule_data (list): A list of dictionaries, where each dictionary represents a rule.

    Returns:
        str: A Markdown table string.
    """
    markdown_table = f"### {section}\n\n"
    markdown_table += "| Rule | Description | Severity |\n"
    markdown_table += "| :--- | :---------- | :------- |\n"
    for rule in rule_data:
        markdown_table += f"| {rule['name']} | {rule['description']} | {rule['severity']} |\n"
    return markdown_table


def main():
    rules_base_dir = "jasapp/rules/dockerfile"

    sections = {
        "Performance": "performance",
        "Security": "security",
        "Syntax": "syntax"
    }

    markdown_output = ""

    for section_name, section_path in sections.items():
        rules_dir = os.path.join(rules_base_dir, section_path)
        rule_data = extract_rule_data(rules_dir)

        # Sort rule data by rule name
        rule_data.sort(key=lambda x: x['name'])

        markdown_output += generate_markdown_table(rule_data, section_name)
        markdown_output += "\n"

    print(markdown_output)


if __name__ == "__main__":
    main()
