#!/usr/bin/env python3
"""Regenerate checked-in Go bindings from a *local*, verified AiCode descriptor set.

Requires Python protobuf and the pinned protoc-gen-go / protoc-gen-go-grpc tools.
Ordinary builds, containers, and CI use the checked-in Go bindings, not this tool.
"""

import argparse
import hashlib
from pathlib import Path
import subprocess

from google.protobuf import descriptor_pb2
from google.protobuf.compiler import plugin_pb2


MODULE = "github.com/ayatinene/ASGemini2API"
PACKAGE = MODULE + "/internal/aicode/pb;pb"
ROOT = Path(__file__).resolve().parents[1]
# The three service/data files used by this gateway, hashed before rewriting Go options.
FILES = {
    "aicode_content.proto": "d15e728fca091cd664d2956e2e803114a44c8d30ae8843f87d5d0ca352bad515",
    "management_service.proto": "fc52ff0b9ccdc804dc29fc0e96d2a8175c0345f33ca7e9dd1c80b28689aa6574",
    "prediction_service.proto": "ca32dae31d221cb5de517264190ac6786e4744e55de9d76359296e86c913727b",
}


def generate(path: Path, plugins: list[str]) -> None:
    with path.open("rb") as source:
        data = source.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("descriptor set is too large")
    descriptor_set = descriptor_pb2.FileDescriptorSet.FromString(data)
    files = {f.name: f for f in descriptor_set.file}
    if len(files) != len(descriptor_set.file):
        raise ValueError("duplicate descriptor file")
    request = plugin_pb2.CodeGeneratorRequest(parameter=f"module={MODULE}")
    request.compiler_version.suffix = "(local FileDescriptorSet)"
    request.file_to_generate.extend(FILES)
    for name, expected in FILES.items():
        actual = hashlib.sha256(files[name].SerializeToString()).hexdigest()
        if expected != actual:
            raise ValueError(f"unexpected descriptor SHA-256 for {name}: {actual}")
        files[name].options.go_package = PACKAGE
    for name in ("google/type/interval.proto",):
        files[name].options.go_package = "google.golang.org/genproto/googleapis/type/interval;interval"

    ordered = set()

    def add(name):
        if name not in ordered:
            ordered.add(name)
            file = files[name]
            for dependency in file.dependency:
                add(dependency)
            request.proto_file.append(file)

    for name in FILES:
        add(name)

    output = {}
    for plugin in plugins:
        raw = subprocess.run([plugin], input=request.SerializeToString(), stdout=subprocess.PIPE, check=True).stdout
        response = plugin_pb2.CodeGeneratorResponse.FromString(raw)
        if response.error:
            raise ValueError(response.error)
        for file in response.file:
            dest = ROOT / file.name
            if dest.parent != ROOT / "internal/aicode/pb" or dest.suffix != ".go" or file.insertion_point or dest in output:
                raise ValueError(f"unexpected generator output: {file.name}")
            output[dest] = file.content
    if len(output) != 5:
        raise ValueError(f"expected five Go files; got {len(output)}")
    for dest, content in output.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        print(dest.relative_to(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("descriptor_set", type=Path)
    parser.add_argument("--go-plugin", default="protoc-gen-go")
    parser.add_argument("--grpc-plugin", default="protoc-gen-go-grpc")
    args = parser.parse_args()
    generate(args.descriptor_set, [args.go_plugin, args.grpc_plugin])


if __name__ == "__main__":
    main()
