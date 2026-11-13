"""Shared deterministic, bounded SQL-only private ZIP serializer (NO publication)."""
from io import BytesIO
import re
import zipfile

MAX_ARCHIVE = 2_000_000
MAX_FILES = 64
MAX_FILE = 100_000
MEMBER = re.compile(r"(?:LICENSE|SOURCE-INPUTS\.json|share/extension/[a-z][a-z0-9_]*(?:--[0-9]+(?:\.[0-9]+)*(?:--[0-9]+(?:\.[0-9]+)*)?\.sql|\.control))\Z")


def require(ok, reason):
    if not ok:
        raise ValueError("SQL_SOURCE_ARCHIVE_DENY: " + reason)


def canonical_zip(members):
    require(type(members) is dict and 3 <= len(members) <= MAX_FILES,
            "unbounded or invalid members")
    require("LICENSE" in members and "SOURCE-INPUTS.json" in members,
            "missing rights or immutable source manifest")
    seen = set()
    for name, data in members.items():
        require(type(name) is str and MEMBER.fullmatch(name) is not None,
                "unsafe source member")
        require(name.casefold() not in seen, "casefold duplicate")
        seen.add(name.casefold())
        require(type(data) is bytes and 0 < len(data) <= MAX_FILE,
                "invalid member bytes")
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, strict_timestamps=True) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    result = stream.getvalue()
    require(0 < len(result) < MAX_ARCHIVE, "archive size")
    return result


def verify_zip(raw, members):
    require(type(raw) is bytes and 0 < len(raw) < MAX_ARCHIVE,
            "unbounded archive")
    expected = canonical_zip(members)
    require(raw == expected, "not canonical exact source ZIP bytes")
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            infos = archive.infolist()
            require([i.filename for i in infos] == sorted(members),
                    "unexpected archive member set/order")
            require(all(i.compress_type == zipfile.ZIP_DEFLATED and
                        i.external_attr >> 16 == 0o100644 and
                        i.date_time == (1980, 1, 1, 0, 0, 0) for i in infos),
                    "unsafe archive member type")
            require(archive.testzip() is None, "corrupt archive CRC")
            for info in infos:
                require(archive.read(info.filename) == members[info.filename],
                        "source member byte mismatch")
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("SQL_SOURCE_ARCHIVE_DENY:"):
            raise
        raise ValueError("SQL_SOURCE_ARCHIVE_DENY: malformed ZIP") from exc
    return True
