import pytest
from pydantic import ValidationError

from lnurl_mint.config import Settings


def test_base_url_is_required(monkeypatch):
    # unlike every other setting, base_url has no default and is never
    # derived from a request's own Host header (see config.py) - an
    # operator who forgets it should get a clear failure at startup, not a
    # silently Host-header-trusting mint
    monkeypatch.delenv("BASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize("rune", [None, ""])
def test_fundingsource_rune_is_loaded_from_path_when_unset_or_empty(tmp_path, rune):
    rune_path = tmp_path / "rune"
    rune_path.write_text("file-rune\n", encoding="utf-8")

    config = Settings(
        base_url="https://mint.example",
        fundingsource_rune=rune,
        fundingsource_rune_path=str(rune_path),
    )

    assert config.fundingsource_rune is not None
    assert config.fundingsource_rune.get_secret_value() == "file-rune"


def test_fundingsource_rune_value_takes_precedence_over_path(tmp_path):
    rune_path = tmp_path / "rune"
    rune_path.write_text("file-rune", encoding="utf-8")

    config = Settings(
        base_url="https://mint.example",
        fundingsource_rune="configured-rune",
        fundingsource_rune_path=str(rune_path),
    )

    assert config.fundingsource_rune is not None
    assert config.fundingsource_rune.get_secret_value() == "configured-rune"
