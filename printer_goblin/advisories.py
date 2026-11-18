"""Vendor security advisory links for reported printer firmware."""

from typing import Optional

# URLs verified 2026-11-18 (HTTP 200, or vendor page confirmed via search where
# the site blocks scripted requests). Star Micronics publishes no advisory page.
_ADVISORY_URLS = {
    "Brother": "https://support.brother.com/g/s/security/en/",
    "HP": "https://support.hp.com/us-en/security-bulletins",
    "Hewlett-Packard": "https://support.hp.com/us-en/security-bulletins",
    "Epson": "https://www.epson.eu/en_EU/faq/KA-01896",
    "Canon": "https://psirt.canon/advisory-information/",
    "Xerox": "https://security.business.xerox.com/en-us/documents/bulletins/",
    "Lexmark": "https://www.lexmark.com/en_us/solutions/security/lexmark-security-advisories.html",
    "Ricoh": "https://www.ricoh.com/products/security/vulnerabilities/product",
    "Kyocera": "https://www.kyoceradocumentsolutions.eu/en/support/security-product-information.html",
    "Konica Minolta": "https://www.konicaminolta.com/global-en/security/advisory/",
    "Sharp": "https://global.sharp/corporate/info/product-security/advisory-list/",
    "Zebra": "https://www.zebra.com/us/en/support-downloads/lifeguard-security/lifeguard-security-alerts.html",
}


def vendor_advisory_url(model: Optional[str]) -> Optional[str]:
    if model:
        normalized = model.strip().casefold()
        return next((url for prefix, url in _ADVISORY_URLS.items()
                     if normalized.startswith(prefix.casefold())), None)
    return None
