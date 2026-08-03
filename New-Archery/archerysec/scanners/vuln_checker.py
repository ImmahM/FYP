# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

import hashlib
import uuid

from webscanners.models import WebScanResultsDb, WebScansDb


def check_false_positive(title, severity, scan_url):
    """
    Build a stable deduplication hash for a vuln within a single scan.
    We normalize case/whitespace and avoid over-keying on URL so the same
    finding reported by multiple phases (spider/passive/active) collapses.
    """
    t = (title or "").strip().lower()
    s = (severity or "").strip().lower()
    # Keep scan_url only as a weak disambiguator if present; normalize it too.
    u = (scan_url or "").strip().lower()
    dup_data = "|".join([t, s, u])
    duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()
    return duplicate_hash
