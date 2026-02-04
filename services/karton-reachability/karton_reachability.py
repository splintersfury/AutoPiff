import os
import json
import subprocess
import shutil
import logging
import tempfile
from karton.core import Karton, Task, Resource
from karton.core.backend import KartonBackend
from jsonschema import validate

class ReachabilityKarton(Karton):
    identity = "AutoPiff.Stage5"
    
    def __init__(self, config=None, backend=None):
        super().__init__(config=config, backend=backend)
        self.schema_path = os.path.join(os.path.dirname(__file__), "reachability.schema.json")
        with open(self.schema_path, "r") as f:
            self.schema = json.load(f)

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        semantic_deltas = task.get_payload("semantic_deltas") # Expecting payload data, or strictly resource?
        # In AutoPiff, stages pass artifacts. Usually as JSON payloads or resources. 
        # Plan says "semantic_deltas.json" artifact.
        
        # If semantic_deltas is a resource, download it.
        # For v1, let's assume it's passed as a JSON payload for simplicity, or we check resources.
        
        # Setup temp dir
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = os.path.join(tmpdir, "driver.sys")
            sample.download_to_file(binary_path)
            
            deltas_path = os.path.join(tmpdir, "semantic_deltas.json")
            if "semantic_deltas" in task.payload:
                with open(deltas_path, 'w') as f:
                    json.dump(task.payload["semantic_deltas"], f)
            else:
                # Handle resource based
                pass # Implementation detail, assuming payload for now based on pattern

            out_path = os.path.join(tmpdir, "reachability.json")
            
            # Run Ghidra Headless
            # Using subprocess to call analyzeHeadless
            # Assumption: analyzeHeadless is in PATH or known location defined by env override
            ghidra_home = os.environ.get("GHIDRA_HOME", "/ghidra")
            headless_script = os.path.join(ghidra_home, "support", "analyzeHeadless")
            
            project_path = os.path.join(tmpdir, "ghidra_proj")
            project_name = "temp_proj"
            
            # Script path: mapped in Docker
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
                # Parse stdout for logic if needed, or just logging
            except subprocess.CalledProcessError as e:
                self.log.error(f"Ghidra failed with exit code {e.returncode}")
                self.log.error(f"STDOUT: {e.stdout.decode(errors='replace')}")
                self.log.error(f"STDERR: {e.stderr.decode(errors='replace')}")
                raise RuntimeError(f"Ghidra analysis failed: {e.stderr.decode(errors='replace')}, stdout: {e.stdout.decode(errors='replace')}")


            if not os.path.exists(out_path):
                raise RuntimeError("Ghidra did not produce output JSON")
                
            with open(out_path, 'r') as f:
                result = json.load(f)
                
            # Validate Schema
            validate(instance=result, schema=self.schema)
            
            # Create output task
            # AutoPiff chain usually: Stage X -> Stage X+1
            # Stage 6 is Ranking
            
            # Upload artifact to MWDB (if that's the pattern) or just pass to next karton
            # Per MEGA_PLAN: "emits a JSON artifact + metadata"
            
            out_task = task.derive_task({
                "reachability": result
            })
            
            # Assuming we route to Stage 6
            # out_task.headers.update({"receiver": "AutoPiff.Stage6"}) # or handled by queue routing
            
            self.send_task(out_task)

if __name__ == "__main__":
    ReachabilityKarton().loop()
