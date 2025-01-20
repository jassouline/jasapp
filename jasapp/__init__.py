"""
Jasapp - A linter for Dockerfiles and Kubernetes manifests with scoring capability.

Features:
- Linting for Dockerfiles and Kubernetes manifests.
- Rules for syntax, security, and performance.
- Scoring system to evaluate file quality on a scale of 100.
"""

__version__ = "0.1.2"
__author__ = "Jordan Assouline"
__license__ = "MIT"

# Import key components for external access
from .cli import main
from .linter import Linter
from .scorer import Scorer
from .parser.dockerfile import DockerfileParser
from .parser.kubernetes import KubernetesParser
from .rules.base_rule import BaseRule
