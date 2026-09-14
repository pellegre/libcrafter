"""Repository paths shared by Wi-Fi reference generators."""

from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[5]
IQ_FIXTURES = REPOSITORY / "crafter/tests/fixtures/iq"
