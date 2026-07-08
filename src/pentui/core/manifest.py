"""Tool manifest schema + loader (PROJECT.md §5).

Manifests are declarative YAML describing how to build a tool's command, which
options need root, the offered profiles, and which parser handles output. They
are validated with Pydantic on load; an invalid manifest raises
``ManifestError`` so the registry can skip it with a clear message rather than
crashing the app.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator


class ManifestError(Exception):
    """Raised when a manifest file is malformed or fails validation."""


class ToolKind(StrEnum):
    """How a tool is executed. ``process`` runs an argv subprocess (every shipped
    tool today); ``rest`` drives an HTTP API instead of a command (e.g. Nessus).
    The workflow engine dispatches on this via ``pentui.core.runner``."""

    PROCESS = "process"
    REST = "rest"


class OptionType(StrEnum):
    BOOL = "bool"  # flag present/absent
    VALUE = "value"  # flag + free-text value
    CHOICE = "choice"  # flag + one of `choices`


class TargetMode(StrEnum):
    APPEND = "append"  # targets appended as trailing argv tokens
    FLAG = "flag"  # targets written to a file passed via `flag`
    FLAG_EACH = "flag_each"  # each target passed inline as `flag <target>` (e.g. -d domain)


class ToolOption(BaseModel):
    flag: str
    label: str
    type: OptionType = OptionType.BOOL
    group: str | None = None
    requires_root: bool = False
    # value / choice
    placeholder: str | None = None
    validate_with: str | None = Field(default=None, alias="validate")
    choices: list[str] = Field(default_factory=list)
    default: str | None = None
    #: Join flag and value into a single token (e.g. "-T4" instead of "-T", "4").
    attached: bool = False
    #: This value option takes a file; if the operator points it at a directory,
    #: the run is batched once per file matching ``file_glob`` (e.g. gowitness -f).
    file_input: bool = False
    file_glob: str = "*"

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _check_choice(self) -> ToolOption:
        if self.type is OptionType.CHOICE and not self.choices:
            raise ValueError(f"option {self.flag!r} is type 'choice' but has no choices")
        if self.default is not None and self.choices and self.default not in self.choices:
            raise ValueError(f"option {self.flag!r} default {self.default!r} not in choices")
        return self


class ToolProfile(BaseModel):
    name: str
    description: str | None = None
    args: list[str] = Field(default_factory=list)
    requires_root: bool = False


class ArtifactSpec(BaseModel):
    flag: str
    #: Output path template; ``{scan_dir}`` is substituted per-scan.
    path: str


class OutputSpec(BaseModel):
    stream: str = "stdout"
    artifact: ArtifactSpec | None = None
    #: Secondary output files written via their own flags (e.g. cewl
    #: ``--email_file``). Emitted into argv with ``{scan_dir}`` templated like
    #: ``artifact``, but never the parsed artifact — they're side outputs.
    extra_artifacts: list[ArtifactSpec] = Field(default_factory=list)
    parser: str | None = None
    #: Whether the tool writes a *directory* of output (screenshots, a DB, files
    #: with fixed names) rather than a single target-named artifact. When True the
    #: run gets its own per-scan subfolder (``scans/<tool>/<target>/``) so those
    #: files never collide; when False (the default) the tool's artifact and log
    #: land flat in the shared tool folder named after the target it scanned
    #: (``scans/<tool>/<target>.xml`` + ``scans/<tool>/logs/<target>.log``),
    #: which avoids a folder-per-target explosion on big fan-outs.
    dir_output: bool = False


class TargetSpec(BaseModel):
    mode: TargetMode = TargetMode.APPEND
    flag: str | None = None

    @model_validator(mode="after")
    def _check_flag(self) -> TargetSpec:
        if self.mode in (TargetMode.FLAG, TargetMode.FLAG_EACH) and not self.flag:
            raise ValueError(f"target.mode {self.mode.value!r} requires a 'flag'")
        return self


class ToolManifest(BaseModel):
    name: str
    binary: str
    description: str | None = None
    #: How the tool runs — an argv subprocess (default) or an HTTP API.
    kind: ToolKind = ToolKind.PROCESS
    version_check: list[str] = Field(default_factory=list)
    #: True when the tool always needs root (raw sockets, privileged binds, …),
    #: regardless of which options/profile are selected.
    requires_root: bool = False
    #: Flag through which an engagement-wide exclude file is passed (e.g.
    #: "--excludefile"). When set and the engagement has exclude scope rules, the
    #: workflow engine writes the file once per run and injects [exclude_flag, path]
    #: into every run. Only tools that natively accept an exclude list set this;
    #: it matters because foreach scans whole /24 CIDRs, which can otherwise sweep
    #: excluded IPs that sit inside an in-scope subnet.
    exclude_flag: str | None = None
    target: TargetSpec = Field(default_factory=TargetSpec)
    output: OutputSpec = Field(default_factory=OutputSpec)
    options: list[ToolOption] = Field(default_factory=list)
    profiles: list[ToolProfile] = Field(default_factory=list)

    def profile(self, name: str) -> ToolProfile | None:
        return next((p for p in self.profiles if p.name == name), None)


def load_manifest(path: str | Path) -> ToolManifest:
    """Load and validate a single manifest YAML file."""
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise ManifestError(f"{path}: could not read/parse YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError(f"{path}: top level must be a mapping")
    try:
        return ToolManifest.model_validate(raw)
    except ValidationError as exc:
        raise ManifestError(f"{path}: invalid manifest:\n{exc}") from exc


def save_manifest(manifest: ToolManifest, path: str | Path) -> Path:
    """Serialize a manifest to YAML that ``load_manifest`` round-trips.

    Used for user-manifest overrides (e.g. saving a new profile). Emits only
    non-default fields so the file stays readable.
    """
    data = manifest.model_dump(by_alias=True, exclude_none=True, exclude_defaults=True, mode="json")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path
