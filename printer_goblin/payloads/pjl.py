"""PJL job wrapper for raw (port 9100) PostScript and PCL jobs.

Many office printers, especially older HP LaserJets, only switch language when a
job says which one follows. Without it, a PostScript job sent to a printer set
to PCL prints as pages of text. This wrapper is a fixed allowlist: it starts a
job, names the language, and ends the job. It never sends @PJL SET, DEFAULT,
FS*, RDYMSG, INQUIRE, or any other command that reads or changes the printer.
"""

UEL = b"\x1b%-12345X"
LANGUAGES = {"ps": b"POSTSCRIPT", "pcl": b"PCL"}
JOB_NAME = b'"Printer Goblin notice"'


def wrap(data: bytes, fmt: str) -> bytes:
    """Return data framed as one PJL job in the given language."""
    if fmt not in LANGUAGES:
        raise ValueError(f"PJL wrapping is only for {', '.join(LANGUAGES)}")
    return (UEL + b"@PJL JOB NAME = " + JOB_NAME + b"\r\n"
            + b"@PJL ENTER LANGUAGE = " + LANGUAGES[fmt] + b"\r\n"
            + data
            + UEL + b"@PJL EOJ NAME = " + JOB_NAME + b"\r\n" + UEL)
