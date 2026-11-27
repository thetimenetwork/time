"""Tests of the timemarket package. Run from clients/python: python -m unittest discover

The vectors are the repository's own (spec/market-vectors.json, written by the engine's tests, and
spec/bitcoin-address-vectors.json): the same files hold the SDK (client-v4/) to the same answers.
"""
import json
from pathlib import Path

SPEC = Path(__file__).resolve().parents[3] / "spec"


def vectors(name: str) -> dict:
    with open(SPEC / name, "r", encoding="utf-8") as file:
        return json.load(file)


ENGINE = vectors("market-vectors.json")
ADDRESSES = vectors("bitcoin-address-vectors.json")
