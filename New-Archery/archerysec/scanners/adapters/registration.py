"""
Auto-registration of all scanner adapters and parsers
"""
from scanners.base import ScannerRegistry
from scanners.adapters import (
    ZAPScannerAdapter, NiktoScannerAdapter, 
    NmapScannerAdapter, OpenVASScannerAdapter
)
from scanners.adapters.parsers import (
    ZAPXMLParserAdapter, NiktoHTMLParserAdapter, 
    NmapXMLParserAdapter, OpenVASXMLParserAdapter
)


def register_default_adapters():
    """Register all default scanner adapters and parsers"""
    # Register scanner adapters
    ScannerRegistry.register_scanner('zap', ZAPScannerAdapter)
    ScannerRegistry.register_scanner('owasp_zap', ZAPScannerAdapter)
    ScannerRegistry.register_scanner('nikto', NiktoScannerAdapter)
    ScannerRegistry.register_scanner('nmap', NmapScannerAdapter)
    ScannerRegistry.register_scanner('openvas', OpenVASScannerAdapter)
    
    # Register parser adapters
    ScannerRegistry.register_parser('web', ZAPXMLParserAdapter)
    ScannerRegistry.register_parser('web', NiktoHTMLParserAdapter)
    ScannerRegistry.register_parser('network', NmapXMLParserAdapter)
    ScannerRegistry.register_parser('network', OpenVASXMLParserAdapter)
    
    # Log registered components
    print(f"Registered scanners: {ScannerRegistry.list_scanners()}")
    print(f"Registered parsers: {ScannerRegistry.list_parsers()}")


# Auto-register on import
register_default_adapters()