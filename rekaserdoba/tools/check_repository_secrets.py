import argparse
import re
import subprocess
from pathlib import Path


PATTERNS = (
    re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[opusr]_[A-Za-z0-9_]{30,}"),
)


def tracked_files(root):
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        check=True,
        capture_output=True,
    )
    return [
        root / value.decode("utf-8")
        for value in result.stdout.split(b"\0")
        if value
    ]


def scan(root):
    matches = []
    for path in tracked_files(root):
        try:
            value = path.read_bytes()
        except OSError:
            continue
        if any(pattern.search(value) for pattern in PATTERNS):
            matches.append(path.relative_to(root).as_posix())
    return matches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, nargs="?", default=Path.cwd())
    args = parser.parse_args()
    matches = scan(args.root.resolve())
    if matches:
        raise SystemExit("potential secret material: " + ", ".join(matches))


if __name__ == "__main__":
    main()
