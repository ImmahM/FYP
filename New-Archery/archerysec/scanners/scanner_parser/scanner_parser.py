# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2022 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# Modified by Victor Sallard (vsallard@scaleway.com)
#
# This file is part of ArcherySec Project.

import glob
import importlib
import os

from django.template.defaulttags import register

parser_function_dict = {}

# Import all modules in the scanner_parser folder
base_dir = os.path.dirname(os.path.abspath(__file__))
module_paths = glob.glob(os.path.join(base_dir, "*", "*.py"), recursive=True)
for module_path in module_paths:
    if os.path.basename(module_path) != "__init__.py" and os.path.basename(module_path) != "scanner_parser.py":
        # Get relative path from base_dir
        rel_path = os.path.relpath(module_path, base_dir)
        # Module name should be like: scanners.scanner_parser.cloud_scanner.prisma_cloud_csv
        module_name = "scanners.scanner_parser." + rel_path.split(".py")[0].replace(os.sep, ".")
        module_id = importlib.import_module(module_name)
        parser_function_dict.update(module_id.parser_header_dict)

# Create a reverse parser dict to ease the lookup for icons
icon_dict = {}
for parser_code in parser_function_dict:
    if "dbname" in parser_function_dict[parser_code]:
        dbName = parser_function_dict[parser_code]["dbname"]
    else:
        dbName = parser_function_dict[parser_code]["dbtype"]

    icon_dict[dbName] = {}
    icon_dict[dbName]["displayName"] = parser_function_dict[parser_code]["displayName"]
    icon_dict[dbName]["codeName"] = parser_code
    icon_dict[dbName]["type"] = parser_function_dict[parser_code]["type"]

    if "icon" in parser_function_dict[parser_code]:
        icon_dict[dbName]["icon"] = parser_function_dict[parser_code]["icon"]


# Django specific definitions
def parser_dict(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    return {"PARSER_DICT": icon_dict}


@register.filter
def get_icon(dictionary, key):
    if not key:
        return "/static/tools/unknown.png"
    k_str = str(key).strip()
    k_lower = k_str.lower()
    if k_lower in ("nikto", "nikto_scan", "nikto scan"):
        return "/static/tools/nikto.svg"
    if k_lower in ("nmap", "nmap_scan", "nmap scan", "additional network scan"):
        return "/static/tools/nmap.svg"
    if k_lower in ("zap", "zapscanner", "web scan"):
        return "/static/tools/zap.png"
    if k_lower in ("openvas", "open_vas", "openvas scan"):
        return "/static/tools/openvas.png"

    if isinstance(dictionary, dict):
        icon = dictionary.get(k_str, {}).get("icon")
        if icon:
            return icon
        for d_key, d_val in dictionary.items():
            if str(d_key).lower() == k_lower and isinstance(d_val, dict) and d_val.get("icon"):
                return d_val["icon"]

    return "/static/tools/unknown.png"


@register.filter
def get_displayName(dictionary, key):
    if not key:
        return "Unknown"
    k_str = str(key).strip()
    k_lower = k_str.lower()
    if k_lower in ("nikto", "nikto_scan", "nikto scan"):
        return "Nikto"
    if k_lower in ("nmap", "nmap_scan", "nmap scan", "additional network scan"):
        return "Nmap"
    if k_lower in ("zap", "zapscanner"):
        return "ZAP"
    if k_lower in ("openvas", "open_vas"):
        return "OpenVAS"

    if isinstance(dictionary, dict):
        dname = dictionary.get(k_str, {}).get("displayName")
        if dname:
            return dname
        for d_key, d_val in dictionary.items():
            if str(d_key).lower() == k_lower and isinstance(d_val, dict) and d_val.get("displayName"):
                return d_val["displayName"]

    return k_str


@register.filter
def get_codeName(dictionary, key):
    return dictionary.get(key, {}).get("codeName", "Unknown name")


@register.filter
def get_type(dictionary, key):
    return dictionary.get(key, {}).get("type", "Unknown type")
