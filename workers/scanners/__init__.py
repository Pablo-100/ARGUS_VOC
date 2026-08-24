"""Scanner abstraction layer.

A scanner adapter converts its native scan results into NormalizedFinding
documents plus a HostObservation per discovered host. The VOC pipeline
(enrich -> enhance -> score -> index -> ticket) only ever consumes normalized
data, so new scanners plug in without touching pipeline logic.
"""
from .base import (HostObservation, NormalizedFinding, ScannerAdapter,
                   KNOWN_SCANNERS, register_scanner)
from .nmap_adapter import NmapAdapter


def get_adapter(name):
    from . import openvas_adapter  # noqa: F401 - registers itself if usable
    return ScannerAdapter.get(name)


__all__ = [
    'HostObservation',
    'NormalizedFinding',
    'ScannerAdapter',
    'KNOWN_SCANNERS',
    'NmapAdapter',
    'get_adapter',
    'register_scanner',
]
