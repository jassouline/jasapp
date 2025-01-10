# Jasapp - Linter for Dockerfiles and Kubernetes Manifests

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Jasapp is a static analysis tool (linter) for configuration files, specifically **Dockerfiles** and **Kubernetes manifests**. It helps identify syntax errors, best practice violations, potential security vulnerabilities, and performance issues. Jasapp is inspired by [Hadolint](https://github.com/hadolint/hadolint) and provides a set of equivalent rules, but written in Python. It also provides a scoring system to assess the overall quality of the analyzed files.

## Features

-   **Dockerfile Analysis:** Jasapp analyzes Dockerfiles and reports errors and warnings based on a set of built-in rules. These rules cover:
    -   **Syntax (STX):**  Verifies syntax, formatting, and instruction order.
    -   **Security (SEC):** Detects security best practice violations.
    -   **Performance (PERF):** Identifies potential optimizations for image size and build speed.
-   **Kubernetes Manifest Analysis:** Jasapp can also analyze Kubernetes manifest files (YAML) and detect structural, security, and best practice issues.
-   **Hadolint Equivalent Rules:** Jasapp implements rules similar to those of Hadolint, allowing for an easy transition for Hadolint users.
-   **Scoring System:** Jasapp calculates a quality score for each analyzed file, based on the number and severity of the detected errors. This score provides a quick indication of the file's quality.
-   **Rule Customization:**
    -   **Ignore Rules:** Ability to ignore specific rules with the `--ignore` option.
    -   **Make Rules Mandatory:** Ability to configure the tool to consider certain errors as blocking (coming soon).
    -   **Add New Rules:** Jasapp is designed to be extensible. New rules can be easily added by inheriting from the `BaseRule` class.
-   **Different Output Formats:** Supports multiple output formats for errors, including:
    -   `console` (default)
    -   `json`
    -   `checkstyle`
    -   `codeclimate`
    -   `gitlab_codeclimate`
    -   `gnu`
    -   `codacy`
    -   `sonarqube`
    -   `sarif`
-   **Configurable Exit Code:** The `--exit-code` option allows setting the exit code to 1 if errors with severity `warning` or `error` are detected.

## Installation

### Prerequisites

-   Python 3.11 or higher
-   pip

### Local Installation (Development Mode)

1.  **Clone the repository:**

    ```bash
    git clone [invalid URL removed] # Replace with your repository URL
    cd jasapp
    ```

2.  **Create a virtual environment (recommended):**

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install the dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

### Installation from PyPI (coming soon)

```bash
pip install jasapp
```

## Using with Docker
