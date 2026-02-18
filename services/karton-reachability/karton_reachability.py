import os
import json
import subprocess
import logging
import tempfile
from karton.core import Karton, Task, Resource
from jsonschema import validate

logger = logging.getLogger("autopiff.reachability")


class ReachabilityKarton(Karton):
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

            # Validate Schema
            validate(instance=result, schema=self.schema)

            # Send to Stage 6 (Ranking)
            out_task = task.derive_task({
                "type": "autopiff",
                "kind": "reachability",
                "reachability": result
            })
            self.send_task(out_task)


if __name__ == "__main__":
    ReachabilityKarton().loop()
