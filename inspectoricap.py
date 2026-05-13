#!/usr/bin/env python
"""
Inspector de dades sensibles en Python.

Flujo general:
1. Recibe ficheros o un directorio desde la CLI.
2. Extrae texto segun el formato.
3. Aplica patrones de datos sensibles.
4. Genera un informe TXT o PDF y devuelve:
   - 0 si no hay datos sensibles.
   - 1 si se detectan datos sensibles.
   - 2 si hay un error de uso.

No requiere dependencias externas. Los extractores integrados son suficientes
para documentos simples; para PDF muy complejos conviene anadir una libreria
especializada como pypdf.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import socketserver
import sys
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree as ET


APP_VERSION = "3.0.0-py"
ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"

SUPPORTED_EXT = {
    "txt", "csv", "log", "md", "ini", "json", "xml", "yaml", "yml",
    "pdf", "docx", "xlsx", "xls", "ods", "odt", "rtf",
    "sql", "conf", "cfg", "env", "properties",
}

SKIP_EXT = {
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz",
    "exe", "dll", "so", "bin", "o", "class",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "ico",
    "mp3", "mp4", "avi", "mov", "wav", "ogg",
    "ttf", "otf", "woff", "woff2",
}


@dataclass(frozen=True)
class PatternDef:
    """Definicion de un tipo de dato sensible."""

    regex: re.Pattern[str]
    ctx: tuple[str, ...]
    always: bool


@dataclass
class Finding:
    """Coincidencias deduplicadas para un tipo de dato sensible."""

    type: str
    matches: list[str]

    @property
    def count(self) -> int:
        return len(self.matches)


@dataclass
class ScanResult:
    """Resultado normalizado de escanear un fichero."""

    file: Path
    filename: str
    size: int
    ext: str
    status: str = "ok"
    message: str = ""
    findings: list[Finding] | None = None
    total: int = 0


def get_patterns() -> dict[str, PatternDef]:
    """
    Devuelve los patrones de datos sensibles.

    - regex: localiza candidatos.
    - ctx: palabras que refuerzan patrones ambiguos.
    - always: si es True, cuenta aunque no haya contexto.
    """

    return {
        "DNI / NIE": PatternDef(
            re.compile(r"\b(?:[0-9]{8}[A-Za-z]|[XYZxyz][0-9]{7}[A-Za-z])\b"),
            ("dni", "nif", "nie", "document", "identif"),
            True,
        ),
        "Telefon": PatternDef(
            re.compile(r"(?<!\d)(?:\+34[\s.\-]?|0034[\s.\-]?)?[6789]\d{2}[\s.\-]?\d{3}[\s.\-]?\d{3}(?!\d)"),
            ("tel", "fax", "movil", "phone", "contacte"),
            True,
        ),
        "Correu electronic": PatternDef(
            re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
            ("email", "correu", "mail"),
            True,
        ),
        "Targeta bancaria": PatternDef(
            re.compile(r"\b(?:4[\d]{3}(?:[\s\-]?[\d]{4}){3}|5[1-5][\d]{2}(?:[\s\-]?[\d]{4}){3}|3[47][\d]{2}(?:[\s\-]?[\d]{6})(?:[\s\-]?[\d]{5})|3(?:0[0-5]|[68][\d])[\d]{2}(?:[\s\-]?[\d]{6})(?:[\s\-]?[\d]{4})|6(?:011|5[\d]{2})(?:[\s\-]?[\d]{4}){3})"),
            ("targeta", "tarjeta", "card", "visa", "mastercard", "card holder", "card number"),
            True,
        ),
        "CVV": PatternDef(
            re.compile(r"\b(?:cvv|cvc|csv|security code)[\s:]*(\d{3,4})\b", re.IGNORECASE),
            ("cvv", "cvc", "card", "targeta"),
            True,
        ),
        "IBAN": PatternDef(
            re.compile(r"\b[A-Z]{2}[0-9]{2}(?:\s?[0-9]{4}){4,6}(?:\s?[0-9]{1,4})?\b"),
            ("iban", "compte", "cuenta", "bank", "transfer"),
            True,
        ),
        "Contrasenya": PatternDef(
            re.compile(r"(?:password|passwd|contrasenya|contrase[nñ]a|pwd|pass|secret|clau|clave|token)\s*[=:]\s*\S+", re.IGNORECASE),
            ("password", "secret", "clau", "clave", "token"),
            True,
        ),
        "Nom i cognoms": PatternDef(
            re.compile(r"\b([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}(?:\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20}){2,3})\b"),
            ("name", "nombre", "nom", "cognoms", "apellido", "titular", "client", "clienta", "signat"),
            False,
        ),
        "Adreca postal": PatternDef(
            re.compile(
                r"(?:Gran\s+Via|Avinguda|Avenida|Avda\.|Avda|Av\.|Av|Travessera|Traves[ií]a|Trav\.|Passatge|Ptge\.|Passeig|Pg\.|Paseo|P\.º|Carrer|Calle|Callej\.|Callejon|Cal|Bulevar|Blv\.|Urbanitzaci[oó]|Urbanizaci[oó]n|Urb\.|Urb|Pol[ií]gonos?|Pol\.|Glorieta|Glta\.|Rambla|Rbla\.|Ronda|Cam[ií]|Camino|Cami|Pla[cç]a|Plaza|Pza\.|Plza\.|Pl\.|Via|C/)"
                r"(?:[^\S\n]+(?:de\s+la|de\s+les|de\s+los|de\s+las|dels|del|de|d'))?"
                r"[^\S\n]+[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ \-]{1,50}[, ]+\d{1,5}"
                r"(?:[, ]+(?:\d{1,3}[rRtTèéaAºª](?: *[0-9a-zA-Z]{1,3})?|[Bb]aixos|[Bb]ajos|[Ee]ntresol|[Pp]rincipal|[Pp]ral\.?|[Áá]tico|[Àà]tic|[Ll]ocal|[Ee]sc\.? *[A-Z]))?"
                r"(?:[ ,\-—]+(?:CP[ .:]*)?[0-5]\d{4}(?: +[A-ZÀ-ÿ][A-Za-zÀ-ÿ \-]{2,30})?)?"
            ),
            (
                "adreça", "adreca", "domicili", "carrer", "avinguda", "passeig",
                "plaça", "placa", "rambla", "camí", "cami", "passatge",
                "dirección", "direccion", "domicilio", "calle", "avenida",
                "paseo", "plaza", "ronda", "bulevar", "urbanizacion",
                "poligono", "adress", "address", "via", "cp",
                "codi postal", "codigo postal",
            ),
            True,
        ),
        "Data de naixement": PatternDef(
            re.compile(r"\b(?:(?:19|20)\d{2}[\-/.](?:0?[1-9]|1[0-2])[\-/.](?:0?[1-9]|[12]\d|3[01])|(?:0?[1-9]|[12]\d|3[01])[\-/.](?:0?[1-9]|1[0-2])[\-/.](?:19|20)\d{2})\b"),
            ("naix", "naci", "born", "birthday", "dob", "data", "fecha"),
            True,
        ),
        "Adreca IP": PatternDef(
            re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
            ("ip", "host", "server", "servidor", "xarxa"),
            False,
        ),
        "Numero SS": PatternDef(
            re.compile(r"\b\d{2}[\s/\-]?\d{8}[\s/\-]?\d{2}\b"),
            ("seguretat social", "seguridad social", "nss"),
            False,
        ),
    }


def norm_val(value: str) -> str:
    """Normaliza texto para deduplicar coincidencias."""

    return re.sub(r"\s+", " ", value).strip().lower()


def is_likely_name_false_positive(value: str) -> bool:
    """
    Descarta falsos positivos de "Nom i cognoms".

    La regex de nombres tambien puede capturar titulos o filas de tabla como
    "Electronics Wireless Mouse Bluetooth". Si contiene vocabulario de
    documentos, productos o estados, no se cuenta como nombre.
    """

    words = re.split(r"\s+", value.strip())
    if len(words) < 3:
        return True

    text = f" {norm_val(value)} "
    non_person_terms = {
        "address", "available", "bluetooth", "bottle", "card", "category",
        "client", "description", "document", "electronics", "email", "fake",
        "holder", "information", "item", "kitchen", "mouse", "notebook",
        "office", "payment", "phone", "sports", "status", "stock",
        "synthetic", "test", "this", "water", "wireless", "yoga",
        "adreca", "adreça", "categoria", "correu", "descripcio",
        "descripció", "disponible", "estat", "telefon", "telèfon",
    }
    return any(f" {term.lower()} " in text for term in non_person_terms)


def ascii85_decode(data: bytes) -> bytes:
    """Decodifica streams PDF con filtro ASCII85Decode."""

    import base64

    chunk = re.sub(rb"\s+", b"", data)
    if not chunk.endswith(b"~>"):
        chunk += b"~>"
    try:
        return base64.a85decode(chunk, adobe=True)
    except Exception:
        return data


def inflate_pdf_stream(data: bytes) -> bytes:
    """Intenta descomprimir un stream PDF FlateDecode."""

    for payload in (data, data[2:]):
        try:
            return zlib.decompress(payload)
        except Exception:
            pass
    return data


def pdf_literal_to_text(value: bytes) -> str:
    """Convierte una cadena literal PDF escapada a texto legible."""

    replacements = {
        rb"\n": b"\n",
        rb"\r": b"\r",
        rb"\t": b"\t",
        rb"\(": b"(",
        rb"\)": b")",
        rb"\\": b"\\",
    }
    out = value
    for old, new in replacements.items():
        out = out.replace(old, new)
    return out.decode("utf-8", errors="ignore") or out.decode("latin-1", errors="ignore")


def extract_pdf(path: Path) -> str:
    """
    Extractor PDF integrado.

    Recorre streams, aplica filtros comunes y busca operadores de texto Tj/TJ.
    Es deliberadamente simple, pero suficiente para muchos PDF generados.
    """

    raw = path.read_bytes()
    text: list[str] = []
    offset = 0

    while True:
        stream_pos = raw.find(b"stream", offset)
        if stream_pos < 0:
            break
        end_pos = raw.find(b"endstream", stream_pos + 6)
        if end_pos < 0:
            break

        dict_region = raw[max(0, stream_pos - 512):stream_pos]
        filter_match = re.search(rb"/Filter\s*(\[.*?\]|/\S+)", dict_region, re.S)
        filter_blob = filter_match.group(1).lower() if filter_match else b""
        filters = re.findall(rb"/([a-z0-9]+(?:decode)?)", filter_blob)

        data_start = stream_pos + 6
        if data_start < len(raw) and raw[data_start:data_start + 1] == b"\r":
            data_start += 1
        if data_start < len(raw) and raw[data_start:data_start + 1] == b"\n":
            data_start += 1
        data = raw[data_start:end_pos]

        if not filters:
            data = inflate_pdf_stream(data)
        for pdf_filter in filters:
            if pdf_filter == b"ascii85decode":
                data = ascii85_decode(data.rstrip())
            elif pdf_filter == b"flatedecode":
                data = inflate_pdf_stream(data)
            elif pdf_filter == b"asciihexdecode":
                hex_data = re.sub(rb"\s|>", b"", data)
                try:
                    data = bytes.fromhex(hex_data.decode("ascii", errors="ignore"))
                except ValueError:
                    pass

        for match in re.finditer(rb"\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*[Tj'\"]", data, re.S):
            text.append(pdf_literal_to_text(match.group(1)))

        for match in re.finditer(rb"\[([^\[\]]*)\]\s*TJ", data, re.S):
            for part in re.finditer(rb"\(([^)\\]*(?:\\.[^)\\]*)*)\)", match.group(1), re.S):
                text.append(pdf_literal_to_text(part.group(1)))
            text.append(" ")

        offset = end_pos + len(b"endstream")

    ascii_chunks = re.findall(rb"[\x20-\x7E]{6,}", raw)
    if ascii_chunks:
        text.append(" ".join(chunk.decode("latin-1", errors="ignore") for chunk in ascii_chunks))

    return " ".join(text)


def xml_text(xml_data: bytes, tags: Iterable[str] | None = None) -> str:
    """Extrae texto de nodos XML, opcionalmente filtrando por nombre local."""

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return ""

    wanted = set(tags or [])
    values: list[str] = []
    for node in root.iter():
        local = node.tag.rsplit("}", 1)[-1]
        if (not wanted or local in wanted) and node.text:
            value = node.text.strip()
            if value:
                values.append(value)
    return " ".join(values)


def extract_docx(path: Path) -> str:
    """Extrae texto de DOCX leyendo document.xml, cabeceras y pies."""

    parts: list[str] = []
    entries = [
        "word/document.xml",
        "word/header1.xml", "word/header2.xml", "word/header3.xml",
        "word/footer1.xml", "word/footer2.xml", "word/footer3.xml",
    ]
    try:
        with zipfile.ZipFile(path) as archive:
            for entry in entries:
                try:
                    parts.append(xml_text(archive.read(entry), {"t"}))
                except KeyError:
                    pass
    except zipfile.BadZipFile:
        return ""
    return "\n".join(part for part in parts if part)


def extract_xlsx(path: Path) -> str:
    """Extrae texto de XLSX resolviendo sharedStrings y valores de celdas."""

    values: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            shared: list[str] = []
            try:
                shared_xml = ET.fromstring(archive.read("xl/sharedStrings.xml"))
                for item in shared_xml.iter():
                    if item.tag.rsplit("}", 1)[-1] == "si":
                        text = " ".join(t.text or "" for t in item.iter() if t.tag.rsplit("}", 1)[-1] == "t")
                        if text.strip():
                            shared.append(text.strip())
            except (KeyError, ET.ParseError):
                pass

            worksheet_names = sorted(name for name in archive.namelist() if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"))
            for name in worksheet_names:
                try:
                    root = ET.fromstring(archive.read(name))
                except ET.ParseError:
                    continue
                for cell in root.iter():
                    if cell.tag.rsplit("}", 1)[-1] != "c":
                        continue
                    cell_type = cell.attrib.get("t", "")
                    value_node = next((n for n in cell if n.tag.rsplit("}", 1)[-1] == "v"), None)
                    if cell_type == "s" and value_node is not None and value_node.text:
                        index = int(value_node.text)
                        if 0 <= index < len(shared):
                            values.append(shared[index])
                    elif cell_type == "inlineStr":
                        values.extend(t.text.strip() for t in cell.iter() if t.tag.rsplit("}", 1)[-1] == "t" and t.text)
                    elif value_node is not None and value_node.text:
                        values.append(value_node.text)
    except (zipfile.BadZipFile, ValueError):
        return ""
    return " ".join(values)


def extract_ods_or_odt(path: Path) -> str:
    """Extrae texto de ODS/ODT desde content.xml."""

    try:
        with zipfile.ZipFile(path) as archive:
            return xml_text(archive.read("content.xml"))
    except (zipfile.BadZipFile, KeyError):
        return ""


def extract_rtf(path: Path) -> str:
    """Extractor RTF simple que elimina grupos y comandos de control."""

    raw = read_text_file(path)
    text = re.sub(r"\{[^{}]*\}", " ", raw)
    text = re.sub(r"\\[a-z]+-?\d*\s?", " ", text)
    return re.sub(r"[{}\\]", " ", text)


def read_text_file(path: Path) -> str:
    """Lee texto plano probando codificaciones comunes."""

    raw = path.read_bytes()
    for encoding in ("utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="ignore")


def extract_text(path: Path) -> str:
    """Selecciona el extractor adecuado segun la extension."""

    ext = path.suffix.lower().lstrip(".")
    if ext == "pdf":
        return extract_pdf(path)
    if ext == "docx":
        return extract_docx(path)
    if ext in {"xlsx", "xls"}:
        return extract_xlsx(path)
    if ext in {"ods", "odt"}:
        return extract_ods_or_odt(path)
    if ext == "rtf":
        return extract_rtf(path)
    return read_text_file(path)


def scan_text(text: str, strict: bool) -> list[Finding]:
    """
    Aplica todos los patrones sobre el texto extraido.

    En modo normal, los patrones ambiguos necesitan contexto. En --strict se
    aceptan aunque no haya contexto.
    """

    findings: list[Finding] = []
    lower_text = text.lower()

    for type_name, pattern in get_patterns().items():
        matches = list(pattern.regex.finditer(text))
        if not matches:
            continue

        if not pattern.always and not strict:
            if not any(ctx.lower() in lower_text for ctx in pattern.ctx):
                continue

        unique: dict[str, str] = {}
        for match in matches:
            original = (match.group(1) if match.lastindex else match.group(0)).strip()
            if type_name == "Nom i cognoms" and is_likely_name_false_positive(original):
                continue
            key = norm_val(original)
            if key and key not in unique:
                unique[key] = original

        if unique:
            findings.append(Finding(type_name, list(unique.values())))

    return findings


def is_binary(path: Path) -> bool:
    """Detecta binarios desconocidos por presencia de bytes nulos."""

    try:
        return path.read_bytes()[:512].count(b"\0") > 2
    except OSError:
        return False


def scan_file(path: Path, strict: bool) -> ScanResult:
    """Escanea un fichero completo y devuelve un resultado normalizado."""

    ext = path.suffix.lower().lstrip(".")
    result = ScanResult(path, path.name, path.stat().st_size if path.exists() else 0, ext, findings=[])

    if ext in SKIP_EXT:
        result.status = "skipped"
        result.message = f"Format ignorat ({ext.upper()})"
        return result
    if not path.is_file() or not os.access(path, os.R_OK):
        result.status = "error"
        result.message = "Sense permisos de lectura"
        return result
    if ext not in SUPPORTED_EXT and is_binary(path):
        result.status = "skipped"
        result.message = "Fitxer binari desconegut"
        return result

    text = extract_text(path)
    if not text.strip():
        result.status = "error"
        result.message = "No s'ha pogut extreure text"
        return result

    findings = scan_text(text, strict)
    total = sum(f.count for f in findings)

    # Evita marcar sensible un documento donde solo aparece un posible nombre.
    if len(findings) == 1 and findings[0].type == "Nom i cognoms" and findings[0].count == 1:
        findings = []
        total = 0

    result.findings = findings
    result.total = total
    result.status = "sensitive" if total > 0 else "ok"
    return result


def decode_bytes(data: bytes) -> str:
    """Convierte bytes a texto probando codificaciones habituales."""

    for encoding in ("utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="ignore")


def guess_extension(data: bytes, filename: str = "") -> str:
    """Deduce extension por nombre o cabecera magica."""

    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    ext = Path(filename).suffix.lower().lstrip(".")
    if ext:
        return ext
    return "txt" if b"\0" not in data[:512] else "bin"


def scan_bytes(data: bytes, filename: str, strict: bool) -> ScanResult:
    """
    Escanea contenido recibido por red.

    Para formatos que necesitan ruta (PDF, DOCX, XLSX, etc.) se crea un fichero
    temporal y se reutiliza scan_file(). Para texto simple se escanea en memoria.
    """

    ext = guess_extension(data, filename)
    safe_name = filename or f"upload.{ext}"

    if ext in SUPPORTED_EXT and ext not in {"txt", "csv", "log", "md", "ini", "json", "xml", "yaml", "yml", "sql", "conf", "cfg", "env", "properties"}:
        suffix = f".{ext}" if ext else ""
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            result = scan_file(tmp_path, strict)
            result.filename = safe_name
            result.file = Path(safe_name)
            result.size = len(data)
            result.ext = ext
            return result
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

    text = decode_bytes(data)
    result = ScanResult(Path(safe_name), safe_name, len(data), ext, findings=[])
    if not text.strip():
        result.status = "error"
        result.message = "No s'ha pogut extreure text"
        return result

    findings = scan_text(text, strict)
    total = sum(f.count for f in findings)
    if len(findings) == 1 and findings[0].type == "Nom i cognoms" and findings[0].count == 1:
        findings = []
        total = 0
    result.findings = findings
    result.total = total
    result.status = "sensitive" if total > 0 else "ok"
    return result


def parse_multipart(body: bytes, content_type: str) -> list[tuple[str, bytes]]:
    """Extrae ficheros de un multipart/form-data HTTP."""

    match = re.search(r'boundary="?([^";]+)"?', content_type, re.IGNORECASE)
    if not match:
        return []

    boundary = ("--" + match.group(1)).encode("latin-1", errors="ignore")
    parts: list[tuple[str, bytes]] = []
    for raw_part in body.split(boundary):
        raw_part = raw_part.strip()
        if not raw_part or raw_part == b"--":
            continue
        if raw_part.endswith(b"--"):
            raw_part = raw_part[:-2].rstrip()
        if b"\r\n\r\n" not in raw_part:
            continue

        header_blob, payload = raw_part.split(b"\r\n\r\n", 1)
        headers = header_blob.decode("latin-1", errors="ignore")
        disposition = next((line for line in headers.splitlines() if line.lower().startswith("content-disposition:")), "")
        filename_match = re.search(r'filename="([^"]+)"', disposition)
        if not filename_match:
            continue

        filename = Path(filename_match.group(1).replace("\\", "/")).name
        parts.append((filename or "upload.bin", payload.rstrip(b"\r\n")))

    return parts


def scan_upload_payload(body: bytes, content_type: str, strict: bool, max_size: int) -> list[ScanResult]:
    """Escanea un cuerpo HTTP completo recibido por ICAP."""

    if len(body) > max_size:
        return [
            ScanResult(
                Path("upload.bin"),
                "upload.bin",
                len(body),
                "bin",
                status="sensitive",
                message=f"Mida maxima superada ({max_size} bytes)",
                findings=[Finding("Mida maxima", [f"{len(body)} bytes"])],
                total=1,
            )
        ]

    parts = parse_multipart(body, content_type)
    if not parts:
        fallback_name = "upload.pdf" if "pdf" in content_type.lower() else "upload.bin"
        parts = [(fallback_name, body)]
    return [scan_bytes(payload, filename, strict) for filename, payload in parts]


def results_are_sensitive(results: list[ScanResult]) -> bool:
    """Indica si algun resultat ha quedat marcat com sensible."""

    return any(result.status == "sensitive" for result in results)


def collect_files(directory: Path, recursive: bool) -> list[Path]:
    """Recoge ficheros de un directorio."""

    iterator = directory.rglob("*") if recursive else directory.iterdir()
    return sorted(path for path in iterator if path.is_file())


def generate_txt(results: list[ScanResult], scan_path: str, elapsed: float) -> str:
    """Construye el informe TXT final."""

    sensitive = sum(1 for result in results if result.status == "sensitive")
    ok = sum(1 for result in results if result.status == "ok")
    skipped = sum(1 for result in results if result.status == "skipped")
    errors = sum(1 for result in results if result.status == "error")
    timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "=" * 60,
        f"  INSPECTOR DE DADES SENSIBLES - v{APP_VERSION}",
        f"  Generat: {timestamp}",
        f"  Ruta:    {scan_path}",
        "=" * 60,
        "",
        "RESUM",
        "-" * 30,
        f"  Total:     {len(results)}",
        f"  Sensibles: {sensitive}",
        f"  Nets:      {ok}",
        f"  Omesos:    {skipped}",
        f"  Errors:    {errors}",
        f"  Temps:     {elapsed}s",
        "",
        "RESULTATS",
        "-" * 60,
    ]

    labels = {
        "sensitive": "[SENSIBLE]",
        "ok": "[NET]     ",
        "skipped": "[OMES]    ",
        "error": "[ERROR]   ",
    }

    for result in results:
        lines.append(f"{labels.get(result.status, '[ERROR]   ')}  {result.filename}")
        if result.status == "sensitive" and result.findings:
            for finding in result.findings:
                lines.append(f"           -> {finding.type} ({finding.count} coincidencies)")
                for match in finding.matches[:10]:
                    lines.append(f"             - {match}")
        if result.message and result.status != "ok":
            lines.append(f"           {result.message}")

    lines.extend(["", "=" * 60])
    return "\n".join(lines) + "\n"


def pdf_escape(text: str) -> str:
    """Escapa texto para meterlo en un stream PDF."""

    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_pdf(results: list[ScanResult], scan_path: str, elapsed: float, output: Path) -> None:
    """Genera un PDF minimo con el informe, sin dependencias externas."""

    lines = generate_txt(results, scan_path, elapsed).splitlines()
    page_width, page_height = 595, 842
    margin, line_height, font_size = 40, 13, 9
    max_lines = (page_height - margin * 2) // line_height
    pages = [lines[i:i + max_lines] for i in range(0, len(lines), max_lines)] or [[]]

    objects: list[bytes] = []
    content_object_numbers: list[int] = []
    page_object_numbers: list[int] = []

    def add_object(payload: bytes) -> int:
        objects.append(payload)
        return len(objects)

    for page_lines in pages:
        stream = [b"BT", f"/F1 {font_size} Tf".encode(), f"{margin} {page_height - margin} Td".encode(), f"{line_height} TL".encode()]
        for line in page_lines:
            safe = pdf_escape(line)
            stream.append(f"({safe}) '".encode("latin-1", errors="replace"))
        stream.append(b"ET")
        content = b"\n".join(stream)
        obj = add_object(b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream")
        content_object_numbers.append(obj)

    pages_obj_placeholder = 0
    for content_obj in content_object_numbers:
        payload = (
            f"<< /Type /Page /Parent {{PAGES}} 0 R /MediaBox [0 0 {page_width} {page_height}] "
            f"/Contents {content_obj} 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Courier >> >> >> >>"
        ).encode()
        page_object_numbers.append(add_object(payload))

    kids = " ".join(f"{num} 0 R" for num in page_object_numbers)
    pages_obj_placeholder = add_object(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_numbers)} >>".encode())
    catalog_obj = add_object(f"<< /Type /Catalog /Pages {pages_obj_placeholder} 0 R >>".encode())

    for index, payload in enumerate(objects):
        objects[index] = payload.replace(b"{PAGES}", str(pages_obj_placeholder).encode())

    output_bytes = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, payload in enumerate(objects, start=1):
        offsets.append(len(output_bytes))
        output_bytes.extend(f"{number} 0 obj\n".encode())
        output_bytes.extend(payload)
        output_bytes.extend(b"\nendobj\n")

    xref_pos = len(output_bytes)
    output_bytes.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output_bytes.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output_bytes.extend(f"{offset:010d} 00000 n \n".encode())
    output_bytes.extend(f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_obj} 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode())
    output.write_bytes(bytes(output_bytes))


def get_icap_header(handler: object, name: str) -> str:
    """Lee una cabecera HTTP/ICAP de pyicap tolerando claves str o bytes."""

    headers = getattr(handler, "headers", {}) or {}
    wanted = name.lower()
    for key, value in getattr(headers, "items", lambda: [])():
        key_text = key.decode("latin-1", errors="ignore") if isinstance(key, bytes) else str(key)
        if key_text.lower() == wanted:
            return value.decode("latin-1", errors="ignore") if isinstance(value, bytes) else str(value)
    return ""


def log_icap_results(results: list[ScanResult], allowed: bool) -> None:
    """Guarda un informe curt de cada peticio ICAP analitzada."""

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    status = "allowed" if allowed else "blocked"
    output = LOG_DIR / f"icap_{status}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.txt"
    output.write_text(generate_txt(results, "ICAP upload", 0), encoding="utf-8")


def run_icap_server(host: str, port: int, strict: bool, max_size: int) -> int:
    """
    Arranca el servidor ICAP REQMOD.

    Requiere instalar pyicap:
        pip install pyicap
    """

    try:
        from pyicap import BaseICAPRequestHandler, ICAPServer
    except ImportError:
        print("ERROR: falta pyicap. Instal-la amb: pip install pyicap", file=sys.stderr)
        return 2

    class ScanHandler(BaseICAPRequestHandler):
        """Handler ICAP que reutilitza la logica DLP de l'inspector."""

        def scan_OPTIONS(self):
            self.set_icap_response(200)
            self.set_icap_header(b"Methods", b"REQMOD")
            self.set_icap_header(b"Service", b"Sensitive Data Inspector ICAP")
            self.set_icap_header(b"Preview", b"0")
            self.set_icap_header(b"Transfer-Complete", b"*")
            self.send_headers(False)

        def scan_REQMOD(self):
            self.read_request_line()
            self.read_headers()

            body = bytearray()
            while True:
                chunk = self.rfile.read(8192)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_size:
                    break

            content_type = get_icap_header(self, "Content-Type")
            results = scan_upload_payload(bytes(body), content_type, strict, max_size)
            allowed = not results_are_sensitive(results)
            log_icap_results(results, allowed)

            if allowed:
                self.set_icap_response(200)
                self.send_headers(True)
                self.write(bytes(body))
            else:
                self.set_icap_response(403)
                self.set_enc_status(b"403 Forbidden")
                self.send_headers(False)

    class ThreadedServer(socketserver.ThreadingMixIn, ICAPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = ThreadedServer((host, port), ScanHandler)
    print(f"ICAP inspector escoltant a {host}:{port} service=scan")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAturant ICAP inspector")
    finally:
        server.server_close()
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Define y parsea argumentos de CLI."""

    parser = argparse.ArgumentParser(description="Inspector de dades sensibles en Python")
    parser.add_argument("paths", nargs="*", help="Fitxers o directoris a inspeccionar")
    parser.add_argument("--dir", dest="directory", help="Inspecciona tots els fitxers d'un directori")
    parser.add_argument("--recursive", "-r", action="store_true", help="Inclou subdirectoris")
    parser.add_argument("--output", "-o", help="Ruta de sortida de l'informe")
    parser.add_argument("--pdf", action="store_true", help="Genera informe PDF")
    parser.add_argument("--txt", action="store_true", help="Genera informe TXT")
    parser.add_argument("--strict", action="store_true", help="Inclou coincidencies sense paraula de context")
    parser.add_argument("--icap", action="store_true", help="Arranca servidor ICAP REQMOD")
    parser.add_argument("--icap-host", default="127.0.0.1", help="Host del servidor ICAP")
    parser.add_argument("--icap-port", type=int, default=1345, help="Port del servidor ICAP")
    parser.add_argument("--icap-max-size", type=int, default=100 * 1024 * 1024, help="Mida maxima d'upload en bytes")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Punto de entrada principal."""

    start = time.time()
    args = parse_args(argv)

    if args.icap:
        return run_icap_server(args.icap_host, args.icap_port, args.strict, args.icap_max_size)

    files: list[Path] = []
    scan_path = ""

    if args.directory:
        directory = Path(args.directory)
        if not directory.is_dir():
            print(f"ERROR: directori no trobat: {directory}", file=sys.stderr)
            return 2
        files = collect_files(directory, args.recursive)
        scan_path = str(directory.resolve())

    for raw_path in args.paths:
        path = Path(raw_path)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(collect_files(path, args.recursive))
            scan_path = str(path.resolve())
        else:
            print(f"Avis: no trobat: {raw_path}", file=sys.stderr)

    if not files:
        print("Us: python inspector.py <fitxer1> [fitxer2] ...")
        print("   python inspector.py --dir <directori> [--recursive]")
        return 0

    if not scan_path:
        scan_path = str(files[0].resolve()) if len(files) == 1 else ", ".join(path.name for path in files)

    results = [scan_file(path, args.strict) for path in files]
    sensitive = sum(1 for result in results if result.status == "sensitive")
    print("No-Ok" if sensitive else "Ok")

    elapsed = round(time.time() - start, 2)
    fmt = "pdf" if args.pdf else "txt"
    if args.output:
        output = Path(args.output)
    else:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        output = LOG_DIR / f"report_py_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"

    if fmt == "pdf":
        generate_pdf(results, scan_path, elapsed, output)
    else:
        output.write_text(generate_txt(results, scan_path, elapsed), encoding="utf-8")

    return 1 if sensitive else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
