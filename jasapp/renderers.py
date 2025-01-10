import json
import xml.etree.ElementTree as ET


class ConsoleRenderer:
    def render(self, errors):
        if errors:
            print("\nLinting errors found:")
            for index, error in enumerate(errors):
                print(self.format_error(error, index))
        else:
            print("\nNo linting errors found.")

    def format_error(self, error, index):
        return (
            f"{index + 1}. [{error['rule']}] Line {error.get('line', 'N/A')}: "
            f"{error['message']} (Severity: {error['severity']})"
        )


class JSONRenderer:
    def render(self, errors):
        print(json.dumps(errors, indent=4))


class CheckstyleRenderer:
    def render(self, errors):
        root = ET.Element("checkstyle")
        for error in errors:
            file_element = ET.SubElement(root, "file", {"name": error.get("file", "unknown")})
            ET.SubElement(file_element, "error", {
                "line": str(error.get("line", "0")),
                "severity": error["severity"],
                "message": error["message"],
                "source": error["rule"]
            })
        print(ET.tostring(root, encoding="unicode"))


class CodeClimateRenderer:
    def render(self, errors):
        issues = []
        for error in errors:
            issue = {
                "type": "issue",
                "check_name": error["rule"],
                "description": error["message"],
                "categories": ["Style"],  # You might want to adjust this based on the rule
                "severity": error["severity"],
                "location": {
                    "path": error.get("file", "unknown"),
                    "lines": {
                        "begin": error.get("line", 0),
                        "end": error.get("line", 0),
                    },
                },
            }
            issues.append(issue)
        print(json.dumps(issues, indent=2))


class GitLabCodeClimateRenderer:
    def render(self, errors):
        issues = []
        for error in errors:
            issue = {
                "type": "issue",
                "check_name": error["rule"],
                "description": error["message"],
                "categories": ["Style"],  # You might want to adjust this based on the rule
                "severity": self.map_severity(error["severity"]),
                "location": {
                    "path": error.get("file", "unknown"),
                    "lines": {
                        "begin": error.get("line", 0),
                    },
                },
                "fingerprint": f"{error['rule']}:{error.get('file', 'unknown')}:{error.get('line', 0)}"
            }
            issues.append(issue)
        print(json.dumps(issues, indent=2))

    def map_severity(self, severity):
        if severity == "error":
            return "blocker"
        elif severity == "warning":
            return "major"
        elif severity == "info":
            return "minor"
        else:
            return "info"


class GNURenderer:
    def render(self, errors):
        for error in errors:
            print(f"{error.get('file', 'unknown')}:{error.get('line', 0)}: {error['severity']}: {error['message']} [{error['rule']}]")


class CodacyRenderer:
    def render(self, errors):
        issues = []
        for error in errors:
            issue = {
                "filename": error.get("file", "unknown"),
                "line": error.get("line", 0),
                "message": error["message"],
                "patternId": error["rule"],
                "severity": self.map_severity(error["severity"]),
            }
            issues.append(issue)
        print(json.dumps(issues, indent=2))

    def map_severity(self, severity):
        if severity == "error":
            return "ERROR"
        elif severity == "warning":
            return "WARNING"
        elif severity == "info":
            return "INFO"
        else:
            return "INFO"


class SonarQubeRenderer:
    def render(self, errors):
        issues = []
        for error in errors:
            issue = {
                "engineId": "jasapp",
                "ruleId": error["rule"],
                "severity": self.map_severity(error["severity"]),
                "type": "CODE_SMELL",
                "primaryLocation": {
                    "message": error["message"],
                    "filePath": error.get("file", "unknown"),
                    "textRange": {
                        "startLine": error.get("line", 0),
                        "endLine": error.get("line", 0),
                        "startColumn": 0,  # You may want to adjust this based on your parsing logic
                        "endColumn": 0,
                    }
                }
            }
            issues.append(issue)
        print(json.dumps({"issues": issues}, indent=2))

    def map_severity(self, severity):
        if severity == "error":
            return "BLOCKER"
        elif severity == "warning":
            return "MAJOR"
        elif severity == "info":
            return "MINOR"
        else:
            return "INFO"


class SARIFRenderer:
    def render(self, errors):
        sarif_output = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Jasapp",
                            "informationUri": "https://github.com/woprandi/jasapp",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        rules_dict = {}
        for error in errors:
            rule_id = error["rule"]
            if rule_id not in rules_dict:
                rule = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": error["description"]  # Assuming you have a description field in your error
                    },
                    "helpUri": f"https://github.com/woprandi/jasapp/blob/main/docs/rules/dockerfile/{rule_id}.md",
                    "properties": {
                        "severity": error["severity"],
                    }
                }
                sarif_output["runs"][0]["tool"]["driver"]["rules"].append(rule)
                rules_dict[rule_id] = rule

            result = {
                "ruleId": rule_id,
                "message": {
                    "text": error["message"]
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": error.get("file", "unknown")
                        },
                        "region": {
                            "startLine": error.get("line", 0)
                        }
                    }
                }],
                "properties": {
                    "severity": error["severity"],
                    "line": error.get("line", 0)
                }
            }
            sarif_output["runs"][0]["results"].append(result)

        print(json.dumps(sarif_output, indent=4))
