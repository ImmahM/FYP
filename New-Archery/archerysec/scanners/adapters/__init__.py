"""
Scanner Adapters
Adapters wrapping existing scanner plugins with the new ScannerBase interface
"""
from .zap_adapter import ZAPScannerAdapter
from .nikto_adapter import NiktoScannerAdapter
from .nmap_adapter import NmapScannerAdapter
from .openvas_adapter import OpenVASScannerAdapter
from .parsers import (
    ZAPXMLParserAdapter, NiktoHTMLParserAdapter,
    NmapXMLParserAdapter, OpenVASXMLParserAdapter
)

__all__ = [
    "ZAPScannerAdapter",
    "NiktoScannerAdapter", 
    "NmapScannerAdapter",
    "OpenVASScannerAdapter",
    "ZAPXMLParserAdapter",
    "NiktoHTMLParserAdapter",
    "NmapXMLParserAdapter",
    "OpenVASXMLParserAdapter",
]