from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_path

from .secure_paths import OwnedPath, ensure_private_directory


@dataclass(frozen=True, slots=True)
class ApplicationPaths:
    root: Path
    data: Path
    logs: Path
    models: Path
    backups: Path
    _identities: tuple[OwnedPath, ...]

    @classmethod
    def create(cls, base: Path | None = None) -> ApplicationPaths:
        requested = (
            Path(base) if base is not None else Path(user_data_path("Tuntun", appauthor=False))
        )
        root_identity = ensure_private_directory(requested)
        identities = (
            root_identity,
            ensure_private_directory(root_identity.path / "data"),
            ensure_private_directory(root_identity.path / "logs"),
            ensure_private_directory(root_identity.path / "models"),
            ensure_private_directory(root_identity.path / "backups"),
        )
        result = cls(
            root=identities[0].path,
            data=identities[1].path,
            logs=identities[2].path,
            models=identities[3].path,
            backups=identities[4].path,
            _identities=identities,
        )
        result.revalidate()
        return result

    def revalidate(self) -> None:
        for identity in self._identities:
            identity.revalidate()
