"""
EEG - Cloud Console Detection
Detects cloud shell environments (Azure Cloud Shell, AWS CloudShell, GCP Cloud Shell)
and provides unified authentication handling.
"""

import os
import subprocess
import json
from typing import Optional, Dict, Tuple


class CloudConsoleDetector:
    """Detect cloud shell environments and provide appropriate auth context."""

    def __init__(self):
        self.console_type: Optional[str] = None
        self.is_cloud_console = False

    def detect(self) -> Tuple[bool, Optional[str], Dict]:
        """
        Detect if running in a cloud console environment.
        Returns: (is_cloud_console, console_type, auth_context)
        """
        # Check Azure Cloud Shell
        if self._is_azure_cloud_shell():
            self.is_cloud_console = True
            self.console_type = "azure"
            return True, "azure", self._get_azure_cloud_shell_context()

        # Check AWS CloudShell
        if self._is_aws_cloudshell():
            self.is_cloud_console = True
            self.console_type = "aws"
            return True, "aws", self._get_aws_cloudshell_context()

        # Check GCP Cloud Shell
        if self._is_gcp_cloud_shell():
            self.is_cloud_console = True
            self.console_type = "gcp"
            return True, "gcp", self._get_gcp_cloud_shell_context()

        return False, None, {}

    # ── Azure Cloud Shell ───────────────────────────────────────────
    def _is_azure_cloud_shell(self) -> bool:
        """Detect Azure Cloud Shell via environment variables."""
        indicators = [
            os.environ.get("AZURE_HTTP_USER_AGENT", "").lower().find("cloudshell") >= 0,
            os.environ.get("POWERSHELL_DISTRIBUTION_CHANNEL", "").lower().find("cloudshell") >= 0,
            os.path.isdir("/home/cloudshell"),
            os.environ.get("ACC_CLOUD") == "AzureCloud",
        ]
        return any(indicators)

    def _get_azure_cloud_shell_context(self) -> Dict:
        """Get auth context from Azure Cloud Shell."""
        context = {
            "provider": "azure",
            "source": "cloud_shell",
            "identity": "cloud_shell_user",
        }
        
        # Get subscription from az cli
        try:
            result = subprocess.run(
                ["az", "account", "show", "--query", "{sub:id,name:name,tenant:tenantId}", "-o", "json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                context["subscription"] = data.get("sub", "")
                context["subscription_name"] = data.get("name", "")
                context["tenant"] = data.get("tenant", "")
        except Exception:
            pass

        # Get current identity
        try:
            result = subprocess.run(
                ["az", "ad", "signed-in-user", "show", "--query", "userPrincipalName", "-o", "tsv"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                context["identity"] = result.stdout.strip()
        except Exception:
            pass

        return context

    # ── AWS CloudShell ──────────────────────────────────────────────
    def _is_aws_cloudshell(self) -> bool:
        """Detect AWS CloudShell via environment variables."""
        indicators = [
            os.environ.get("AWS_EXECUTION_ENV") == "CloudShell",
            os.environ.get("AWS_CLOUDSHELL_USER_ID") is not None,
            "/home/cloudshell-user" in os.environ.get("HOME", ""),
        ]
        return any(indicators)

    def _get_aws_cloudshell_context(self) -> Dict:
        """Get auth context from AWS CloudShell."""
        context = {
            "provider": "aws",
            "source": "cloud_shell",
            "region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")),
        }

        # Get caller identity
        try:
            result = subprocess.run(
                ["aws", "sts", "get-caller-identity", "--output", "json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                context["account"] = data.get("Account", "")
                context["identity"] = data.get("Arn", "").split("/")[-1]
                context["user_arn"] = data.get("Arn", "")
        except Exception:
            pass

        return context

    # ── GCP Cloud Shell ─────────────────────────────────────────────
    def _is_gcp_cloud_shell(self) -> bool:
        """Detect GCP Cloud Shell via environment variables."""
        indicators = [
            os.environ.get("CLOUD_SHELL") == "true",
            os.environ.get("DEVSHELL_GCLOUD_CONFIG") is not None,
            os.path.isdir("/google/devshell"),
        ]
        return any(indicators)

    def _get_gcp_cloud_shell_context(self) -> Dict:
        """Get auth context from GCP Cloud Shell."""
        context = {
            "provider": "gcp",
            "source": "cloud_shell",
            "project": os.environ.get("DEVSHELL_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", "")),
        }

        # Get current user
        try:
            result = subprocess.run(
                ["gcloud", "config", "get-value", "account"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                context["identity"] = result.stdout.strip()
        except Exception:
            pass

        # Get project if not set
        if not context.get("project"):
            try:
                result = subprocess.run(
                    ["gcloud", "config", "get-value", "project"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    context["project"] = result.stdout.strip()
            except Exception:
                pass

        return context


class LocalConsoleAuthenticator:
    """Handle authentication for local console environments."""

    def __init__(self, cloud_env: str):
        self.cloud_env = cloud_env.lower()

    def check_cli_auth(self) -> Tuple[bool, Dict]:
        """
        Check if local CLI tools are authenticated.
        Returns: (is_authenticated, auth_context)
        """
        dispatch = {
            "azure": self._check_azure_cli,
            "aws": self._check_aws_cli,
            "gcp": self._check_gcp_cli,
        }
        handler = dispatch.get(self.cloud_env)
        if handler:
            return handler()
        return False, {}

    def _check_azure_cli(self) -> Tuple[bool, Dict]:
        """Check Azure CLI authentication status."""
        try:
            result = subprocess.run(
                ["az", "account", "show", "-o", "json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return True, {
                    "provider": "azure",
                    "source": "azure_cli",
                    "subscription": data.get("id", ""),
                    "subscription_name": data.get("name", ""),
                    "tenant": data.get("tenantId", ""),
                    "identity": data.get("user", {}).get("name", "unknown"),
                }
        except Exception:
            pass
        return False, {}

    def _check_aws_cli(self) -> Tuple[bool, Dict]:
        """Check AWS CLI authentication status."""
        try:
            result = subprocess.run(
                ["aws", "sts", "get-caller-identity", "--output", "json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return True, {
                    "provider": "aws",
                    "source": "aws_cli",
                    "account": data.get("Account", ""),
                    "identity": data.get("Arn", "").split("/")[-1],
                    "region": os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
                }
        except Exception:
            pass
        return False, {}

    def _check_gcp_cli(self) -> Tuple[bool, Dict]:
        """Check GCP gcloud CLI authentication status."""
        try:
            result = subprocess.run(
                ["gcloud", "auth", "list", "--filter=status:ACTIVE", "--format=json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if data:
                    account = data[0].get("account", "unknown")
                    # Get project
                    proj_result = subprocess.run(
                        ["gcloud", "config", "get-value", "project"],
                        capture_output=True, text=True, timeout=10
                    )
                    project = proj_result.stdout.strip() if proj_result.returncode == 0 else "unknown"
                    return True, {
                        "provider": "gcp",
                        "source": "gcloud_cli",
                        "identity": account,
                        "project": project,
                    }
        except Exception:
            pass
        return False, {}
