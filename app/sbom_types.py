from __future__ import annotations

from typing import TypedDict


class Metadata(TypedDict):
    name: str
    version: str
    creation_date: str
    supplier: str
    spec_version: str


class Component(TypedDict):
    name: str
    version: str
    licenses: list[str]
    purl: str
    type: str
    supplier: str
    hashes: dict[str, str]
    description: str


NormalizedDependency = TypedDict(
    "NormalizedDependency",
    {"from": str, "to": list[str], "type": str},
)


class NormalizedSBOM(TypedDict):
    metadata: Metadata
    components: list[Component]
    dependencies: list[NormalizedDependency]
