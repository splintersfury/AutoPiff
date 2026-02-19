import os
import json
import subprocess
import logging
import tempfile
from karton.core import Karton, Task, Resource
from jsonschema import validate
from mwdblib import MWDB

logger = logging.getLogger("autopiff.reachability")


class ReachabilityKarton(Karton):
    """
    AutoPiff Stage 5: Reachability Tagging.

    Runs Ghidra headless analysis on the driver binary to trace
    call paths from dispatch entry points (DriverEntry, IRP handlers,
    IOCTL dispatchers) to each changed function, classifying
    reachability as ioctl, irp, pnp, internal, or unknown.

    Consumes: type=autopiff, kind=semantic_deltas
    Produces: type=autopiff, kind=reachability
    """

    identity = "AutoPiff.Stage5"
    filters = [
        {"type": "autopiff", "kind": "semantic_deltas"}
    ]

    def __init__(self, config=None, backend=None):
        super().__init__(config=config, backend=backend)
        self.schema_path = os.environ.get(
            "AUTOPIFF_REACHABILITY_SCHEMA",
            os.path.join(os.path.dirname(__file__), "reachability.schema.json")
        )
        with open(self.schema_path, "r") as f:
            self.schema = json.load(f)

        # MWDB connection for uploading decompiled source
        self.mwdb_url = os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/")
        self.mwdb_key = os.environ.get("MWDB_API_KEY", "")

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        if not sample:
            self.log.error("No sample resource in task")
            return

        semantic_deltas = task.get_payload("semantic_deltas")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Write binary to disk from resource content
            binary_path = os.path.join(tmpdir, "driver.sys")
            with open(binary_path, "wb") as f:
                f.write(sample.content)

            # Write semantic deltas to disk
            deltas_path = os.path.join(tmpdir, "semantic_deltas.json")
            if semantic_deltas:
                with open(deltas_path, 'w') as f:
                    json.dump(semantic_deltas, f)
            else:
                self.log.error("No semantic_deltas payload in task")
                return

            out_path = os.path.join(tmpdir, "reachability.json")

            # Run Ghidra Headless
            ghidra_home = os.environ.get("GHIDRA_HOME", "/ghidra")
            headless_script = os.path.join(ghidra_home, "support", "analyzeHeadless")

            project_path = os.path.join(tmpdir, "ghidra_proj")
            project_name = "temp_proj"

            script_path = "/app/ghidra/scripts/autopiff_reachability.py"

            cmd = [
                headless_script,
                project_path,
                project_name,
                "-import", binary_path,
                "-postScript", script_path, out_path, deltas_path,
                "-deleteProject"
            ]

            self.log.info(f"Running Ghidra: {' '.join(cmd)}")

            timeout = int(os.environ.get("AUTOPIFF_GHIDRA_TIMEOUT", "900"))
            try:
                proc = subprocess.run(cmd, check=True, timeout=timeout, capture_output=True)
            except subprocess.CalledProcessError as e:
                self.log.error(f"Ghidra failed with exit code {e.returncode}")
                self.log.error(f"STDOUT: {e.stdout.decode(errors='replace')}")
                self.log.error(f"STDERR: {e.stderr.decode(errors='replace')}")
                raise RuntimeError(f"Ghidra analysis failed: {e.stderr.decode(errors='replace')}")
            except subprocess.TimeoutExpired as e:
                self.log.error(f"Ghidra timed out after {timeout}s")
                raise RuntimeError(f"Ghidra analysis timed out after {timeout}s")

            if not os.path.exists(out_path):
                raise RuntimeError("Ghidra did not produce output JSON")

            with open(out_path, 'r') as f:
                result = json.load(f)

            # Upload decompiled .c to MWDB (best-effort, don't block pipeline)
            decomp_path = result.get("decompiled_c_path")
            if decomp_path and os.path.exists(decomp_path):
                sha256 = result.get("driver", {}).get("sha256", "")
                self._upload_decompiled_c(decomp_path, sha256)
            else:
                self.log.warning("No decompiled .c produced by Ghidra script")

            # Validate Schema
            validate(instance=result, schema=self.schema)

            # Send to Stage 6 (Ranking)
            out_task = task.derive_task({
                "type": "autopiff",
                "kind": "reachability",
                "reachability": result
            })
            self.send_task(out_task)


    def _upload_decompiled_c(self, decomp_path, sha256):
        """Upload decompiled .c to MWDB as child of the driver sample."""
        if not self.mwdb_key:
            self.log.warning("No MWDB_API_KEY set, skipping decompiled .c upload")
            return

        try:
            mwdb = MWDB(api_url=self.mwdb_url, api_key=self.mwdb_key)
        except Exception as e:
            self.log.error(f"Failed to connect to MWDB: {e}")
            return

        if not sha256:
            self.log.error("No driver sha256, cannot upload decompiled .c")
            return

        try:
            parent = mwdb.query_file(sha256)
        except Exception as e:
            self.log.warning(f"Could not find parent sample {sha256}: {e}")
            parent = None

        try:
            with open(decomp_path, "rb") as f:
                content = f.read()

            uploaded = mwdb.upload_file(
                f"{sha256[:12]}_decompiled.c",
                content,
                parent=parent,
            )
            uploaded.add_tag("ghidra_decompiled")
            uploaded.add_tag("source_c")
            self.log.info(f"Uploaded decompiled .c ({len(content)} bytes): {uploaded.sha256}")
        except Exception as e:
            self.log.error(f"Failed to upload decompiled .c: {e}")


if __name__ == "__main__":
    ReachabilityKarton().loop()
