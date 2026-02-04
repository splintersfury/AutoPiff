import json
import jsonschema
from jsonschema import validate

schema_path = "/home/splintersfury/Documents/AutoPiff/schemas/reachability.schema.json"

with open(schema_path, 'r') as f:
    schema = json.load(f)

# Valid Mock Data
valid_data = {
    "autopiff_stage": "reachability",
    "driver": {
        "sha256": "a" * 64,
        "arch": "x86_64"
    },
    "dispatch": {
        "driver_entry": "DriverEntry",
        "major_functions": {
            "IRP_MJ_CREATE": "sub_140001000",
            "IRP_MJ_CLOSE": None,
            "IRP_MJ_DEVICE_CONTROL": "sub_140002000",
            "IRP_MJ_INTERNAL_DEVICE_CONTROL": None
        }
    },
    "ioctls": [
        {
            "ioctl": "0x222000",
            "handler": "sub_140005000",
            "confidence": 0.9,
            "evidence": ["switch_on_IoControlCode"]
        }
    ],
    "tags": [
        {
            "function": "sub_140005000",
            "reachability_class": "ioctl",
            "confidence": 0.95,
            "paths": ["IRP_MJ_DEVICE_CONTROL -> sub_140005000"],
            "evidence": ["direct_callgraph_edge", "ioctl_case_call"]
        }
    ],
    "notes": ["Test note"]
}

# Run Validation
try:
    validate(instance=valid_data, schema=schema)
    print("SUCCESS: Valid data passed schema check.")
except Exception as e:
    print(f"FAILURE: {e}")

# Invalid Data Check (Missing required key)
invalid_data = valid_data.copy()
del invalid_data['dispatch']
try:
    validate(instance=invalid_data, schema=schema)
    print("FAILURE: Invalid data passed check (should fail).")
except jsonschema.ValidationError:
    print("SUCCESS: Invalid data failed check as expected.")
