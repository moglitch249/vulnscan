"""Nmap scanner integration.

Runs nmap as a subprocess, captures XML output, and parses results
into the framework's domain models. Uses shell=False and validated
inputs to prevent command injection.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

from vulnscanner.core.logging import get_logger
from vulnscanner.core.models import (
    DiscoveredHost,
    DiscoveredPort,
    DiscoveredService,
    ScanProfile,
)
from vulnscanner.core.scanner_base import ScanResult, ScannerIntegration
from vulnscanner.integrations.nmap.parser import NmapParseResult, NmapXMLParser

logger = get_logger(__name__)


# Default Nmap arguments per scan profile
_PROFILE_ARGS: dict[str, list[str]] = {
    "quick": ["-sn", "-T4", "--max-retries", "1"],
    "standard": ["-sV", "--top-ports", "1000", "-T3", "--max-retries", "2"],
    "deep": ["-sV", "-sC", "-O", "-p-", "-T3", "--max-retries", "2"],
    "web": ["-sV", "-p", "80,443,8080,8443,8000,8888,3000,5000,9443", "-T3", "--script", "http-title,http-server-header,ssl-cert"],
}


class NmapScanner(ScannerIntegration):
    """Nmap integration — runs scans and parses XML output."""

    def __init__(
        self,
        nmap_binary: str = "nmap",
        timeout: int = 600,
        scan_run_id: UUID | None = None,
    ) -> None:
        self._binary = nmap_binary
        self._timeout = timeout
        self._scan_run_id = scan_run_id
        self._parser = NmapXMLParser()

    @property
    def name(self) -> str:
        return "nmap"

    async def is_available(self) -> bool:
        """Check if nmap binary is on PATH."""
        path = shutil.which(self._binary)
        if path is None:
            logger.warning("nmap_not_found", binary=self._binary)
            return False

        # Try running nmap --version to verify
        try:
            proc = await asyncio.create_subprocess_exec(
                self._binary, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            version_output = stdout.decode("utf-8", errors="replace")
            logger.info("nmap_found", binary=path, output=version_output.split("\n")[0])
            return True
        except Exception as exc:
            logger.warning("nmap_check_failed", error=str(exc))
            return False

    async def scan(
        self,
        targets: list[str],
        profile: ScanProfile,
        extra_args: list[str] | None = None,
    ) -> ScanResult:
        """Run an Nmap scan against targets.

        Args:
            targets: List of validated IPs, hostnames, or CIDRs.
            profile: Scan profile determining intensity.
            extra_args: Additional nmap arguments.

        Returns:
            ScanResult with discovered hosts, ports, and services.
        """
        if not targets:
            return ScanResult(scanner_name=self.name, errors=["No targets provided"])

        # Build nmap command
        profile_args = _PROFILE_ARGS.get(profile.value, _PROFILE_ARGS["standard"])

        # Create temp file for XML output
        with tempfile.NamedTemporaryFile(
            suffix=".xml", prefix="vulnscan_nmap_", delete=False, mode="w"
        ) as tmp:
            xml_output_path = tmp.name

        try:
            # Construct command — NEVER use shell=True
            cmd = [
                self._binary,
                *profile_args,
                "-oX", xml_output_path,  # XML output to file
                "--noninteractive",
            ]

            # Add extra args if provided
            if extra_args:
                cmd.extend(extra_args)

            # Add targets last
            cmd.extend(targets)

            logger.info(
                "nmap_scan_starting",
                targets=targets,
                profile=profile.value,
                command=" ".join(cmd),
            )

            # Run nmap
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                error_msg = f"Nmap scan timed out after {self._timeout}s"
                logger.error("nmap_timeout", timeout=self._timeout)
                return ScanResult(scanner_name=self.name, errors=[error_msg])

            stdout_text = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                error_msg = f"Nmap exited with code {proc.returncode}: {stderr_text}"
                logger.error("nmap_failed", returncode=proc.returncode, stderr=stderr_text[:500])
                return ScanResult(
                    scanner_name=self.name,
                    errors=[error_msg],
                    raw_output=stdout_text,
                )

            # Parse XML output
            xml_file = Path(xml_output_path)
            if not xml_file.exists() or xml_file.stat().st_size == 0:
                return ScanResult(
                    scanner_name=self.name,
                    errors=["Nmap produced no XML output"],
                    raw_output=stdout_text,
                )

            xml_content = xml_file.read_text(encoding="utf-8", errors="replace")
            parsed = self._parser.parse(xml_content, self._scan_run_id)

            logger.info(
                "nmap_scan_completed",
                hosts=len(parsed.hosts),
                ports=len(parsed.ports),
                services=len(parsed.services),
                elapsed=parsed.metadata.get("elapsed", "?"),
            )

            return ScanResult(
                scanner_name=self.name,
                hosts=parsed.hosts,
                ports=parsed.ports,
                services=parsed.services,
                raw_output=xml_content,
                metadata=parsed.metadata,
            )

        finally:
            # Clean up temp file
            try:
                Path(xml_output_path).unlink(missing_ok=True)
            except OSError:
                pass

    async def scan_from_file(self, xml_path: str) -> ScanResult:
        """Import and parse a previously generated Nmap XML file.

        Args:
            xml_path: Path to existing Nmap XML output file.

        Returns:
            ScanResult from the parsed XML.
        """
        path = Path(xml_path)
        if not path.exists():
            return ScanResult(
                scanner_name=self.name,
                errors=[f"File not found: {xml_path}"],
            )

        try:
            xml_content = path.read_text(encoding="utf-8", errors="replace")
            parsed = self._parser.parse(xml_content, self._scan_run_id)

            logger.info(
                "nmap_file_imported",
                file=xml_path,
                hosts=len(parsed.hosts),
                ports=len(parsed.ports),
                services=len(parsed.services),
            )

            return ScanResult(
                scanner_name=self.name,
                hosts=parsed.hosts,
                ports=parsed.ports,
                services=parsed.services,
                raw_output=xml_content,
                metadata=parsed.metadata,
            )
        except Exception as exc:
            error_msg = f"Failed to parse Nmap XML: {exc}"
            logger.error("nmap_parse_failed", error=str(exc), file=xml_path)
            return ScanResult(scanner_name=self.name, errors=[error_msg])

    async def parse_output(self, raw_output: str | bytes) -> ScanResult:
        """Parse raw Nmap XML output.

        Args:
            raw_output: Nmap XML string or bytes.

        Returns:
            ScanResult.
        """
        try:
            if isinstance(raw_output, bytes):
                raw_output = raw_output.decode("utf-8", errors="replace")

            parsed = self._parser.parse(raw_output, self._scan_run_id)
            return ScanResult(
                scanner_name=self.name,
                hosts=parsed.hosts,
                ports=parsed.ports,
                services=parsed.services,
                raw_output=raw_output,
                metadata=parsed.metadata,
            )
        except Exception as exc:
            return ScanResult(
                scanner_name=self.name,
                errors=[f"Parse error: {exc}"],
                raw_output=raw_output if isinstance(raw_output, str) else None,
            )
