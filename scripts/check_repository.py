#!/usr/bin/env python3
"""Validate public repository content without reading ignored local research."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

try:
    import yaml
except ImportError:
    sys.exit("Install validation tools: python -m pip install -r requirements-dev.txt")


class UniqueKeyLoader(yaml.BaseLoader):
    """Keep YAML scalars as strings and reject ambiguous duplicate keys."""

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError(f"duplicate YAML key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def public_files(root: Path) -> list[str]:
    output = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
    )
    return sorted(set(output.decode().split("\0")) - {""})


def private_path(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        ".intel" in path.parts
        or (path.name.startswith(".env") and not path.name.endswith(".example"))
        or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".zip"}
    )


def prose_lines(text: str):
    """Skip fenced code blocks when checking Markdown destinations."""
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            yield re.sub(r"`+[^`]*`+", "", line)


def markdown_links(text: str):
    for line in prose_lines(text):
        for match in re.finditer(r"!?\[[^\]]*\]\(\s*(<[^>]+>|[^\s)]+)", line):
            yield match.group(1).strip("<>")
        reference = re.match(r"^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)", line)
        if reference:
            yield reference.group(1).strip("<>")


def local_api_references(document):
    if isinstance(document, dict):
        for key, value in document.items():
            if key == "$ref" and isinstance(value, str) and value.startswith("#/"):
                yield value
            yield from local_api_references(value)
    elif isinstance(document, list):
        for value in document:
            yield from local_api_references(value)


def check_repository(root: Path) -> tuple[list[str], int]:
    names = public_files(root)
    public = set(names)
    errors = []
    documents = {}

    for probe in [".intel/probe", "docs/.intel/probe", "nested/deep/.intel/probe"]:
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", probe], cwd=root
        )
        if result.returncode != 0:
            errors.append(f".gitignore must exclude {probe}")

    for name in names:
        if private_path(name):
            errors.append(f"local-only or sensitive file in public file list: {name}")
            continue
        path = root / name
        if path.is_symlink():
            errors.append(f"public symlink requires an explicit policy: {name}")
            continue
        if not path.is_file():
            errors.append(f"public file is missing: {name}")
            continue
        if path.suffix not in {".md", ".json", ".yaml", ".yml", ".py", ".txt"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
            if content and not content.endswith("\n"):
                errors.append(f"missing final newline: {name}")
            if path.suffix == ".json":
                documents[name] = json.loads(content)
            elif path.suffix in {".yaml", ".yml"}:
                documents[name] = yaml.load(content, Loader=UniqueKeyLoader)
            elif path.suffix == ".md":
                for link in markdown_links(content):
                    parsed = urlsplit(link)
                    if parsed.scheme or parsed.netloc or not parsed.path:
                        continue
                    destination = unquote(parsed.path)
                    target = (
                        root / destination.lstrip("/")
                        if destination.startswith("/")
                        else path.parent / destination
                    ).resolve()
                    try:
                        relative = target.relative_to(root).as_posix()
                    except ValueError:
                        errors.append(f"link escapes repository in {name}: {link}")
                        continue
                    available = relative in public or (
                        target.is_dir()
                        and any(item.startswith(relative.rstrip("/") + "/") for item in public)
                    )
                    if not available:
                        errors.append(f"missing or nonpublic link in {name}: {link}")
        except (UnicodeError, ValueError, yaml.YAMLError) as error:
            errors.append(f"invalid document {name}: {error}")

    labels = documents.get(".github/labels.json", [])
    label_names = set()
    if not isinstance(labels, list):
        errors.append(".github/labels.json must contain an array")
        labels = []
    for label in labels:
        if not isinstance(label, dict):
            errors.append("label definitions must be objects")
            continue
        name = label.get("name")
        if not isinstance(name, str) or not name or len(name) > 50:
            errors.append("label names must be strings of 1 to 50 characters")
            continue
        if name.casefold() in label_names:
            errors.append(f"duplicate label: {name}")
        label_names.add(name.casefold())
        if not re.fullmatch(r"[0-9a-fA-F]{6}", str(label.get("color", ""))):
            errors.append(f"invalid label color: {name}")
        description = label.get("description")
        if not isinstance(description, str) or len(description) > 100:
            errors.append(f"invalid label description: {name}")

    for name, document in documents.items():
        if name.startswith(".github/ISSUE_TEMPLATE/") and isinstance(document, dict):
            for label in document.get("labels", []):
                if label.casefold() not in label_names:
                    errors.append(f"undefined issue-form label in {name}: {label}")
        if name.endswith(".openapi.yaml"):
            for reference in local_api_references(document):
                target = document
                try:
                    for part in reference[2:].split("/"):
                        target = target[part.replace("~1", "/").replace("~0", "~")]
                except (KeyError, TypeError):
                    errors.append(f"unresolved API reference in {name}: {reference}")

    return errors, len(names)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors, count = check_repository(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Repository checks passed ({count} public files).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
