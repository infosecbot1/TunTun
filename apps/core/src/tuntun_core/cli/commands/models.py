from __future__ import annotations

import json
from pathlib import Path

import typer
from platformdirs import user_data_path
from tuntun_core.services.models.installer import ModelInstaller
from tuntun_core.services.models.registry import ModelEntry, ModelRegistry

models_app = typer.Typer(no_args_is_help=True, help="Manage governed local model artifacts.")
_REPOSITORY_ROOT = Path(__file__).parents[6]
_REPOSITORY_MANIFEST = _REPOSITORY_ROOT / "models" / "manifest.yaml"
_PACKAGED_MANIFEST = Path(__file__).parents[2] / "resources" / "model-manifest.yaml"
_MODEL_ROOT = Path(user_data_path("Tuntun", appauthor=False)) / "models"
_DOWNLOAD_HOSTS = frozenset({"alphacephei.com"})


def _manifest_path() -> Path:
    if _REPOSITORY_MANIFEST.is_file():
        return _REPOSITORY_MANIFEST
    if _PACKAGED_MANIFEST.is_file():
        return _PACKAGED_MANIFEST
    raise FileNotFoundError("governed model manifest is unavailable")


def _registry() -> ModelRegistry:
    return ModelRegistry.load(_manifest_path(), model_root=_MODEL_ROOT)


def _public_entry(entry: ModelEntry) -> dict[str, object]:
    public_entry: dict[str, object] = {
        "id": entry.model_id,
        "revision": entry.revision,
        "runtime": entry.runtime,
        "files": [
            {"path": item.path, "size": item.size, "sha256": item.sha256} for item in entry.files
        ],
    }
    if entry.calibration_report_sha256 is not None and entry.runtime_download is not None:
        public_entry["calibration_report_sha256"] = entry.calibration_report_sha256
        public_entry["runtime_download"] = entry.runtime_download
    return public_entry


@models_app.command("list")
def list_models() -> None:
    """List governed manifest entries without activating or downloading them."""
    typer.echo(json.dumps([_public_entry(entry) for entry in _registry().models]))


@models_app.command()
def verify() -> None:
    """Verify every installed governed revision without network access."""
    registry = _registry()
    verified: list[dict[str, object]] = []
    for entry in registry.models:
        if not (_MODEL_ROOT / entry.model_id).is_dir():
            continue
        activated = registry.activate(entry.model_id)
        try:
            if not activated.all_files_verified:
                raise typer.Exit(1)
            verified.append(_public_entry(entry))
        finally:
            activated.close()
    typer.echo(json.dumps(verified))


@models_app.command()
def install(
    model_id: str,
    approve: bool = typer.Option(
        False,
        "--approve",
        help="Confirm this owner-invoked network download and immutable publication.",
    ),
) -> None:
    """Explicitly download, verify, and publish one governed model revision."""
    if not approve:
        raise typer.BadParameter("--approve is required for model installation")
    registry = _registry()
    activated = ModelInstaller(registry, _DOWNLOAD_HOSTS).install(model_id)
    try:
        if not activated.all_files_verified:
            raise typer.Exit(1)
        typer.echo(json.dumps(_public_entry(registry.entry(model_id))))
    finally:
        activated.close()
