import os
from collections.abc import Mapping
from dataclasses import dataclass


class DatabaseConfigurationError(ValueError):
    """Raised when database configuration is absent or unsafe."""


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    url: str
    echo: bool = False

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> "DatabaseConfig":
        values = os.environ if environment is None else environment
        url = values.get("FORGESOC_DATABASE_URL")

        if not url:
            raise DatabaseConfigurationError(
                "FORGESOC_DATABASE_URL is required"
            )

        if not url.startswith("postgresql+psycopg://"):
            raise DatabaseConfigurationError(
                "FORGESOC_DATABASE_URL must use postgresql+psycopg"
            )

        echo = values.get("FORGESOC_DATABASE_ECHO", "false").lower() in {
            "1",
            "true",
            "yes",
        }
        return cls(url=url, echo=echo)
