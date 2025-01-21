# Jasapp - Linter for Dockerfiles and Kubernetes Manifests

<img src="jasapp/doc/logo.png" alt="Jasapp Logo" width="250">

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
    git clone https://gitlab.com/jassouline/jasapp.git
    cd jasapp
    ```

2.  **Create a virtual environment (recommended):**

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install the dependencies:**

    ```bash
    pip install -r requirements.txt .
    ```

### Installation from PyPI

```bash
pip install jasapp
```

### Using with Docker

```bash
docker run --rm jassouline/jasapp --type dockerfile --score - < path_to_your_dockerfile
```

## Usage

### Command Syntax:

```bash
jasapp <file> --type <type> [options]
```

### Arguments:

- `<file>` : Path to the file to analyze (Dockerfile or Kubernetes manifest)
- `--type <type>` : File type (required) : `dockerfile` or `kubernetes`

### Options:

- `--score` : Displays the quality score of the file (between 0 and 100)
- `--ignore <rule1> <rule2> ...` : ignores the specified rules (e.g., --ignore STX0001 STX0002)
- `--format <format>` : specified the output format for errors (default : `console`). Available formats are : `console`, `json`, `checkstyle`, `codeclimate`, `gitlab_codeclimate`, `gnu`, `codacy`, `sonarqube`, `sarif`
- `--exit-code` : returns an exit code of 1 if errors with severity `warning` or `error` area detected, 0 otherwise.
- `--version` : displays the current version of `jasapp`

### Examples:

- Analyze a Dockerfile and display the score:

```bash
jasapp examples/dockerfile/example.Dockerfile --type dockerfile --score
```

- Analyze a Kubernetes manifest with JSON output format:
  
```bash
jasapp examples/kubernetes/example.yaml --type kubernetes --format json
```

- Ignore rules `STX0001` and `PERF0001`:
  
```bash
jasapp examples/dockerfile/example.Dockerfile --type dockerfile --ignore STX0001 PERF0001
```

- Use the `--exit-code` option to integrate Jasapp into a CI/CD pipeline:

```bash
jasapp examples/dockerfile/example.Dockerfile --type dockerfile --exit-code
```

## Dockerfile 
### Performance

| Rule | Description | Severity |
| :--- | :---------- | :------- |
| PERF0001 | `useradd` without flag `-l` and high UID will result in excessively large image. | warning |
| PERF0002 | Avoid use of wget without progress bar. Use `wget --progress=dot:giga <url>`. Or consider using `-q` or `-nv` (shorthands for `--quiet` or `--no-verbose`). | info |
| PERF0004 | Multiple consecutive `RUN` instructions. Consider consolidation. | info |
| PERF0005 | Either use `wget` or `curl` but not both | warning |
| PERF0006 | Use `COPY --chown` instead of separate `RUN chown` | info |

### Security

| Rule | Description | Severity |
| :--- | :---------- | :------- |
| SEC0001 | The last USER in each stage should not be root. | warning |
| SEC0002 | Do not use 'sudo' in RUN instructions as it leads to unpredictable behavior. Use a tool like 'gosu' to enforce root instead. | error |
| SEC0003 | Add a HEALTHCHECK dockerfile instruction to perform the health check on running containers. | info |
| SEC0004 | Do not use `update` instructions alone in the Dockerfile. | info |
| SEC0005 | Avoid mounting sensitive directories in Docker volumes | error |
| SEC0006 | Hardcoded secrets found in `ENV`, `ARG`, or `RUN` instruction. | error |
| SEC0011 | Insecure file permissions set with `chmod` in `RUN` instruction | warning |
| SEC0012 | Potentially dangerous shell command used in `RUN` instruction | warning |
| SEC0013 | `curl` command in `RUN` instruction is disabling certificate validation. | error |
| SEC0014 | `wget` command in `RUN` instruction is disabling certificate validation. | error |
| SEC0015 | `pip` command in `RUN` instruction is using `--trusted-host` option, which disables certificate validation. | error |
| SEC0016 | `PYTHONHTTPSVERIFY` environment variable is set to `0`, disabling HTTPS certificate verification. | error |
| SEC0017 | `NODE_TLS_REJECT_UNAUTHORIZED` environment variable is set to `0`, disabling TLS certificate validation. | error |
| SEC0018 | `apk` is configured to allow untrusted repositories. | error |
| SEC0019 | `apt` or `apt-get` is configured to allow unauthenticated packages. | error |
| SEC0020 | `yum` is configured to skip GPG signature checks. | error |
| SEC0021 | `rpm` is configured to skip package signature checks. | error |
| SEC0022 | `apt-get install` is used without `-y` or with `--force-yes` or `--allow-unauthenticated`, which can bypass prompts and verifications. | error |
| SEC0023 | `npm config set strict-ssl false` is used, which disables strict SSL verification. | error |
| SEC0024 | `npm` configuration is modified to disable strict SSL verification. | error |
| SEC0025 | `git` is configured to disable SSL verification. | error |
| SEC0026 | `yum` is configured to disable SSL verification. | error |
| SEC0027 | `pip` command in `RUN` instruction is using `--trusted-host` option. | warning |
| SEC0028 | Port 22 is exposed, which can pose a security risk. | warning |
| SEC0029 | No `USER` instruction found in the Dockerfile. Consider adding a non-root user. | warning |

### Syntax

| Rule | Description | Severity |
| :--- | :---------- | :------- |
| STX0001 | Ensure WORKDIR uses an absolute path. | error |
| STX0002 | Avoid using the 'latest' tag in Docker images. | warning |
| STX0003 | Avoid using commands like `ssh`, `vim`, `shutdown`, `service`, `ps`, `free`, `top`, `kill`, `mount`, or `ifconfig` in Dockerfiles as they are not applicable in a containerized environment. | info |
| STX0004 | Use WORKDIR to switch to a directory instead of 'cd' in RUN instructions. | warning |
| STX0005 | Always tag the version of an image explicitly in FROM instructions. | warning |
| STX0006 | Avoid using the 'latest' tag in FROM instructions. Pin the version explicitly to a release tag. | warning |
| STX0007 | Ensure versions are pinned in `apt-get install` commands to prevent unpredictable behavior. | warning |
| STX0008 | Ensure that `apt` or `apt-get` lists are deleted after installing packages to reduce image size. | info |
| STX0010 | Use `ADD` for extracting archives into an image. | info |
| STX0011 | Ensure exposed ports are within the valid UNIX port range (0 to 65535). | error |
| STX0012 | Ensure there is only one HEALTHCHECK instruction in the Dockerfile. | error |
| STX0013 | Pin versions in pip install. Instead of `pip install <package>` use `pip install <package>==<version>` or `pip install --requirement <requirements file>`. | warning |
| STX0014 | Use the `-y` switch to avoid manual input in `apt-get install <package>`. | warning |
| STX0015 | Avoid additional packages by specifying `--no-install-recommends` in `apt-get install` commands. | info |
| STX0016 | Pin versions in npm. Instead of `npm install <package>` use `npm install <package>@<version>`. | warning |
| STX0017 | Pin versions in apk add. Instead of `apk add <package>` use `apk add <package>=<version>`. | warning |
| STX0018 | Use the `--no-cache` switch to avoid the need to use `--update` and remove `/var/cache/apk/*` when done installing packages. | info |
| STX0019 | Use COPY instead of ADD for files and folders. | error |
| STX0020 | COPY with more than 2 arguments requires the last argument to end with '/'. | error |
| STX0021 | `COPY --from` should reference a previously defined `FROM` alias. | warning |
| STX0022 | `COPY --from` cannot reference its own `FROM` alias. | error |
| STX0023 | FROM aliases (stage names) must be unique. | error |
| STX0024 | Use arguments JSON notation for CMD and ENTRYPOINT arguments. | warning |
| STX0025 | Use only an allowed registry in the FROM image | error |
| STX0026 | Do not use apt as it is meant to be an end-user tool, use apt-get or apt-cache instead. | warning |
| STX0027 | Pin versions in gem install. Instead of `gem install <gem>` use `gem install <gem>:<version>` | warning |
| STX0028 | Do not use --platform flag with FROM, unless it's a variable like BUILDPLATFORM or TARGETPLATFORM | warning |
| STX0029 | Use the -y switch to avoid manual input `yum install -y <package>` | warning |
| STX0030 | `yum clean all` should be present after `yum install` commands. | warning |
| STX0031 | Specify version with `yum install -y <package>-<version>`. | warning |
| STX0032 | Non-interactive switch missing from `zypper` command: `zypper --non-interactive install <package>` | warning |
| STX0033 | Do not use `zypper dist-upgrade` or `zypper dup`. | warning |
| STX0034 | `zypper clean` should be present after `zypper install` or `zypper in` commands. | warning |
| STX0035 | Specify version with `zypper install -y <package>-<version>`. | warning |
| STX0036 | Use the -y switch to avoid manual input `dnf install -y <package>` | warning |
| STX0037 | `dnf clean all` or `rm -rf /var/cache/yum/*` should be present after `dnf install` commands. | warning |
| STX0038 | Specify version with `dnf install -y <package>-<version>` or `dnf module install -y <module>:<version>`. | warning |
| STX0039 | Avoid using cache directory with pip. Use `pip install --no-cache-dir <package>` | warning |
| STX0040 | `ONBUILD`, `FROM`, or `MAINTAINER` should not be triggered from within `ONBUILD` instruction. | error |
| STX0041 | Do not refer to an environment variable within the same `ENV` statement where it is defined. | error |
| STX0042 | `COPY` to a relative destination without `WORKDIR` set. | warning |
| STX0043 | Invalid label key. | info |
| STX0044 | Required label is missing. | info |
| STX0045 | Superfluous label present. | info |
| STX0046 | Label is empty. | warning |
| STX0047 | Label value is not a valid URL. | warning |
| STX0048 | Label value is not a valid RFC3339 timestamp. | warning |
| STX0049 | Label value is not a valid SPDX identifier. | warning |
| STX0050 | Label value is not a valid Git hash. | warning |
| STX0051 | Label value is not a valid email address. | warning |
| STX0052 | `yarn cache clean` missing after `yarn install` was run. | info |
| STX0053 | Invalid instruction order. Dockerfile must begin with `FROM`, `ARG`, a comment, or a parser directive. | error |
| STX0054 | `MAINTAINER` is deprecated | error |
| STX0055 | Multiple `CMD` instructions found. If you list more than one `CMD` then only the last `CMD` will take effect. | warning |
| STX0056 | Multiple `ENTRYPOINT` instructions found. If you list more than one `ENTRYPOINT` then only the last `ENTRYPOINT` will take effect. | error |
| STX0057 | Use `SHELL` to change the default shell | warning |
| STX0063 | `USER` instruction used before `WORKDIR`, `COPY`, or `ADD` within the same stage | warning |
| STX0064 | `RUN` instruction after `CMD` or `ENTRYPOINT` | warning |


## Kubernetes 
### Performance

| Rule | Description | Severity |
| :--- | :---------- | :------- |
| K8S-PERF-0001 | CPU limits are not set for container. | warning |
| K8S-PERF-0002 | Memory requests are not set for container. | warning |
| K8S-PERF-0003 | Memory limits are not set for container. | warning |
| K8S-PERF-0004 | CPU requests are not set for container. | warning |

### Security

| Rule | Description | Severity |
| :--- | :---------- | :------- |
| K8S-SEC-0001 | Containers should not be allowed to share the host's process ID namespace. | error |
| K8S-SEC-0002 | Containers should not be privileged. | error |
| K8S-SEC-0003 | Containers should not share the host's process ID namespace. | warning |
| K8S-SEC-0004 | Containers should not share the host's IPC namespace. | warning |
| K8S-SEC-0005 | Containers should not share the host's network namespace. | warning |
| K8S-SEC-0006 | Containers should not allow privilege escalation. | warning |
| K8S-SEC-0008 | Containers should use a read-only root filesystem. | info |
| K8S-SEC-0010 | Containers should only add specific capabilities. | info |
| K8S-SEC-0010 | Containers should not use hostPort. | info |
| K8S-SEC-0011 | Containers should drop all capabilities and add only those required. | info |
| K8S-SEC-0013 | Containers should not mount the Docker socket. | warning |
| K8S-SEC-0014 | Containers should drop the NET_RAW capability unless explicitly allowed. | info |
| K8S-SEC-0015 | `securityContext` is not applied to pods or containers. | info |
| K8S-SEC-0017 | Containers should not share the host's IPC namespace. | warning |
| K8S-SEC-0018 | Seccomp profile should be set to `RuntimeDefault` or `DockerDefault`. | info |
| K8S-SEC-0019 | Kubernetes dashboard is deployed. | info |
| K8S-SEC-0020 | Tiller (Helm V2) is deployed, which has known security risks. | info |
| K8S-SEC-0021 | Secrets should not be used as environment variables. | info |
| K8S-SEC-0022 | Containers should drop all capabilities and add only those required. | info |
| K8S-SEC-0023 | Service account tokens should not be mounted unless explicitly set to false. | info |
| K8S-SEC-0024 | Containers should not add the `CAP_SYS_ADMIN` capability. | error |
| K8S-SEC-0025 | Containers should be configured to run with a high UID (>= 10000). | info |
| K8S-SEC-0026 | The default service account should not be actively used. | info |
| K8S-SEC-0027 | Containers should not share the host's network namespace. | warning |
| K8S-SEC-0028 | Tiller (Helm V2) deployment is accessible from within the cluster. | info |
| K8S-SEC-0029 | Tiller (Helm V2) service should be deleted from the cluster. | info |
| K8S-SEC-0030 | Containers should not be allowed to run as root. | warning |
| K8S-SEC-0031 | Containers should drop the NET_RAW capability or drop ALL capabilities. | info |

### Syntax

| Rule | Description | Severity |
| :--- | :---------- | :------- |
| K8S-STX-0001 | Image tag is not set to a specific version. Avoid 'latest' or no tag. | warning |
| K8S-STX-0002 | `imagePullPolicy` is not set to `Always`. | warning |
| K8S-STX-0004 | Avoid using the 'default' namespace in Kubernetes resources. | info |
| K8S-STX-0004 | Image tag should be a digest (sha256) for immutability. | info |
| K8S-STX-0006 | Containers should have a liveness probe configured. | info |
| K8S-STX-0007 | Containers should have a readiness probe configured. | info 