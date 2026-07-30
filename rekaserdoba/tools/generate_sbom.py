import argparse
import json
import uuid
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def component(package):
    name = package["name"]
    version = package["version"]
    value = {
        "type": "library",
        "name": name,
        "version": version,
        "bom-ref": f"pkg:cargo/{name}@{version}",
        "purl": f"pkg:cargo/{name}@{version}",
    }
    if "checksum" in package:
        value["hashes"] = [{"alg": "SHA-256", "content": package["checksum"]}]
    return value


def generate(lock_path, version, commit):
    packages = tomllib.loads(Path(lock_path).read_text(encoding="utf-8"))["package"]
    components = sorted(
        (component(package) for package in packages),
        key=lambda value: (value["name"], value["version"]),
    )
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        "\n".join([version, commit, *(value["bom-ref"] for value in components)]),
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "rekaserdoba-server",
                "version": version,
                "properties": [{"name": "git:commit", "value": commit}],
            }
        },
        "components": components,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    value = generate(args.lock, args.version, args.commit)
    args.output.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
