#!/usr/local/bin/python3
"""
Inspector de dades sensibles en Python.

Flujo general:
1. Recibe ficheros o un directorio desde la CLI.
2. Extrae texto segun el formato.
3. Aplica patrones de datos sensibles y, si esta disponible, NER multilingue.
4. Genera un informe TXT o PDF y devuelve:
   - 0 si no hay datos sensibles.
   - 1 si se detectan datos sensibles.
   - 2 si hay un error de uso.

No requiere dependencias externas para funcionar. Si transformers/torch estan
instalados, anade deteccion NER multilingue compatible con catalan, castellano
e ingles; para PDF muy complejos conviene anadir una libreria especializada
como pypdf.
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
import urllib.parse
import zipfile
import zlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET


APP_VERSION = "3.1.0-py"
ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
ICAP_SERVER_NAME = b"SensitiveDataInspector/3.1"
UPLOAD_METHODS = {"PUT", "POST", "PATCH"}
BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs",
    ".jar", ".dll", ".scr", ".pif",
}
BLOCKED_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sh",
    "application/java-archive",
    "application/x-bat",
    "application/x-msdos-program",
}
DEFAULT_NER_MODEL = "Babelscape/wikineural-multilingual-ner"
LOCAL_NER_MODEL_DIR = ROOT / "models" / "wikineural-multilingual-ner"
NER_MIN_SCORE = 0.75
NER_MAX_TEXT_CHARS = 250_000
NER_LOAD_ERROR = ""

PERSON_CONTEXT = (
    "name", "full name", "first name", "last name", "surname", "holder",
    "customer", "client", "contact", "signatory", "representative",
    "nombre", "nombre y apellidos", "apellidos", "apellido", "titular",
    "cliente", "clienta", "contacto", "firmante", "representante",
    "solicitante", "nom", "nom i cognoms", "cognoms", "cognom",
    "titular", "client", "clienta", "contacte", "signat", "signant",
    "representant", "sol.licitant", "sol·licitant",
)

ADDRESS_CONTEXT = (
    "address", "street", "road", "avenue", "postcode", "postal code",
    "adreça", "adreca", "domicili", "carrer", "avinguda", "passeig",
    "plaça", "placa", "rambla", "camí", "cami", "passatge",
    "dirección", "direccion", "domicilio", "calle", "avenida", "paseo",
    "plaza", "ronda", "bulevar", "urbanización", "urbanizacion",
    "polígono", "poligono", "cp", "codi postal", "codigo postal",
)

NAME_TOKEN = r"[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ'·.-]{1,30}"
NAME_PARTICLE = r"(?:d'|de|del|de[^\S\n]+la|de[^\S\n]+les|de[^\S\n]+los|de[^\S\n]+las|dels|dos|da|van|von|y|i)"
PERSON_NAME_REGEX = (
    rf"{NAME_TOKEN}(?:[^\S\n]+(?:{NAME_PARTICLE}[^\S\n]+)?{NAME_TOKEN}){{1,4}}"
)
ORG_SUFFIX = r"(?:S\.?L\.?U?|S\.?L\.?|S\.?A\.?|SLL|SCP|S\.? Coop\.?|Coop\.?|Associaci[oó]|Fundaci[oó]|Ute|UTE)"
ORG_CONTEXT = (
    "empresa", "societat", "sociedad", "company", "entitat", "entidad",
    "proveidor", "proveedor", "contractista", "organisme", "organismo",
    "ajuntament", "agencia", "agència", "administracio", "administració",
)
ADDRESS_TYPE = (
    r"Gran\s+Via|Avinguda|Avenida|Avenue|Avda\.?|Ave\.?|Av\.?|Travessera|"
    r"Traves[ií]a|Trav\.|Passatge|Ptge\.|Passeig|Pg\.|Paseo|P\.º|Carrer|"
    r"Calle|Street|St\.|Road|Rd\.|Lane|Ln\.|Drive|Dr\.|Callej\.|Callejon|"
    r"Callejón|Cal|Bulevar|Blv\.|Boulevard|Urbanitzaci[oó]|Urbanizaci[oó]n|"
    r"Urb\.?|Pol[ií]gonos?|Pol\.|Glorieta|Glta\.|Rambla|Rbla\.|Ronda|"
    r"Cam[ií]|Camino|Cami|Pla[cç]a|Plaza|Pza\.|Plza\.|Pl\.|Via|C/"
)
ADDRESS_REGEX = (
    rf"(?:{ADDRESS_TYPE})"
    r"(?:[^\S\n]+(?:de\s+la|de\s+les|de\s+los|de\s+las|dels|del|de|d'))?"
    r"[^\S\n]+[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'\-]{1,70}"
    r"(?:[, ]+|[^\S\n]+(?:num\.?|n[uú]m\.?|n[ºo]\.?)[^\S\n]*)"
    r"\d{1,5}[A-Za-z]?"
    r"(?:[, ]+(?:\d{1,3}[rRtTèéaAºª](?: *[0-9a-zA-Z]{1,3})?|[Bb]aixos|"
    r"[Bb]ajos|[Ee]ntresol|[Pp]rincipal|[Pp]ral\.?|[Áá]tico|[Àà]tic|"
    r"[Ll]ocal|[Ee]sc\.? *[A-Z]))?"
    r"(?:[ ,\-—]+(?:CP|C\.?P\.?|ZIP|Postcode|Postal code)?[ .:]*"
    r"(?:[0-5]\d{4}|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})"
    r"(?: +[A-ZÀ-ÿ][A-Za-zÀ-ÿ \-]{2,30})?)?"
)

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
            ("dni", "nif", "nie", "document", "documento", "identity", "id", "identif"),
            True,
        ),
        "NIF empresa / CIF": PatternDef(
            re.compile(r"\b(?:ES\s*)?[ABCDEFGHJKLMNPQRSUVW][\s-]?\d{7}[\s-]?[0-9A-J]\b", re.IGNORECASE),
            ("nif", "cif", "empresa", "societat", "sociedad", "company", "entitat", "entidad"),
            True,
        ),
        "Empresa / organisme": PatternDef(
            re.compile(
                rf"\b([A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÿ0-9&.'-]{{1,40}}(?:[^\S\n]+(?:de|del|dels|la|les|los|las|i|y|and|the|[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÿ0-9&.'-]{{1,40}})){{1,8}}[^\S\n]+{ORG_SUFFIX})\b",
                re.IGNORECASE,
            ),
            ORG_CONTEXT,
            True,
        ),
        "Matricula vehicle": PatternDef(
            re.compile(r"\b(?:[0-9]{4}[\s-]?[BCDFGHJKLMNPRSTVWXYZ]{3}|[A-Z]{1,2}[\s-]?[0-9]{4}[\s-]?[A-Z]{1,2})\b", re.IGNORECASE),
            ("matricula", "matrícula", "placa", "vehicle", "vehiculo", "vehículo", "license plate", "number plate"),
            True,
        ),
        "Codi segur de verificacio (CSV)": PatternDef(
            re.compile(r"\b(?:CSV|codi(?: segur)?(?: de verificacio| de verificació)?|c[oó]digo(?: seguro)?(?: de verificaci[oó]n)?|secure verification code|verification code)\s*[:=\s]\s*([A-Z0-9]+(?:-[A-Z0-9]+){1,5})\b", re.IGNORECASE),
            ("csv", "codi segur", "codigo seguro", "código seguro", "verificacio", "verificació", "verificacion", "verificación", "secure verification code"),
            True,
        ),
        "Telefon": PatternDef(
            re.compile(r"(?<!\d)(?:\+34[\s.\-]?|0034[\s.\-]?)?[6789]\d{2}[\s.\-]?\d{3}[\s.\-]?\d{3}(?!\d)"),
            ("tel", "fax", "movil", "móvil", "mobile", "phone", "telephone", "contacte", "contacto", "contact"),
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
            re.compile(r"\b(?:cvv|cvc|csc|security code)[\s:]*(\d{3,4})\b", re.IGNORECASE),
            ("cvv", "cvc", "csc", "card", "targeta"),
            True,
        ),
        "IBAN": PatternDef(
            re.compile(r"\b[A-Z]{2}[0-9]{2}(?:\s?[0-9]{4}){4,6}(?:\s?[0-9]{1,4})?\b"),
            ("iban", "compte", "cuenta", "account", "bank", "banc", "banco", "transfer", "transferencia"),
            True,
        ),
        "Contrasenya": PatternDef(
            re.compile(r"(?:password|passwd|contrasenya|contrase[nñ]a|pwd|pass|secret|clau|clave|token)\s*[=:]\s*\S+", re.IGNORECASE),
            ("password", "secret", "clau", "clave", "token"),
            True,
        ),
        "Nom i cognoms": PatternDef(
            re.compile(
                rf"(?:\b(?:nom(?:\s+i\s+cognoms)?|nombre(?:\s+y\s+apellidos)?|full\s+name|name|apellidos?|cognoms?|titular|clienta?|cliente|customer|contacte|contacto|contact|signat(?:ari)?|signant|firmante|representant|representante|sol[.·]?licitant|solicitante)\s*[:=\-]\s*)?({PERSON_NAME_REGEX})\b"
            ),
            PERSON_CONTEXT,
            True,
        ),
        "Adreca postal": PatternDef(
            re.compile(ADDRESS_REGEX, re.IGNORECASE),
            ADDRESS_CONTEXT,
            True,
        ),
        "Adreca postal etiquetada": PatternDef(
            re.compile(
                rf"\b(?:adre[cç]a|domicili(?:\s+social)?|direcci[oó]n|direccion|address)\s*[:=\-]\s*({ADDRESS_REGEX})"
                r"|\b(?:carrer|calle)\s*[:=\-]\s*([A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'\-]{1,70}(?:[, ]+|[^\S\n]+(?:num\.?|n[uú]m\.?|n[ºo]\.?)[^\S\n]*)\d{1,5}[A-Za-z]?(?:[ ,\-—]+(?:CP|C\.?P\.?)?[ .:]*[0-5]\d{4}(?: +[A-ZÀ-ÿ][A-Za-zÀ-ÿ \-]{2,30})?)?)",
                re.IGNORECASE,
            ),
            ADDRESS_CONTEXT,
            True,
        ),
        "Adreca postal contextual": PatternDef(
            re.compile(
                rf"\b(?:domicili(?:\s+a\s+efectes\s+de\s+comunicaci[oó])?|adre[cç]a|direcci[oó]n|direccion|address)[^.\n]{{0,80}}?\s+a\s+([A-ZÀ-ÿ][A-Za-zÀ-ÿ .'\-]{{2,50}},\s*{ADDRESS_REGEX})",
                re.IGNORECASE,
            ),
            ADDRESS_CONTEXT,
            True,
        ),
        "Adreca postal anglesa": PatternDef(
            re.compile(
                r"\b[A-ZÀ-ÿ][A-Za-zÀ-ÿ .'\-]{1,60}[^\S\n]+(?:Street|St\.|Road|Rd\.|Avenue|Ave\.|Lane|Ln\.|Drive|Dr\.|Boulevard|Blvd\.)[, ]+\d{1,5}[A-Za-z]?"
                r"(?:[ ,\-]+(?:ZIP|Postcode|Postal code)?[ .:]*(?:\d{5}(?:-\d{4})?|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}))?\b",
                re.IGNORECASE,
            ),
            ADDRESS_CONTEXT,
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


def clean_match_value(type_name: str, value: str) -> str:
    """Recorta artefactos habituales de extraccion antes de deduplicar."""

    value = re.sub(r"\s+", " ", value).strip(" \t\r\n.;,")
    next_label = (
        "DNI", "NIE", "NIF", "Telefon", "Telèfon", "Telefono", "Teléfono",
        "Correu", "Correo", "Email", "Adreca", "Adreça", "Direccion",
        "Dirección", "Address", "Matricula", "Matrícula", "IBAN", "CSV",
        "Contrasenya", "Contraseña", "Password",
    )
    label_pattern = r"\s+(?:" + "|".join(re.escape(label) for label in next_label) + r")\b.*$"
    if type_name in {"Adreca postal", "Adreca postal anglesa", "Adreca postal etiquetada", "Adreca postal contextual", "Contrasenya"}:
        value = re.sub(label_pattern, "", value, flags=re.IGNORECASE).strip(" \t\r\n.;,")
    if type_name == "Contrasenya":
        value = value.rstrip(")")
    if type_name == "Nom i cognoms":
        value = re.sub(r"^(?:en|el|la|els|les|sr\.?|sra\.?|senyor|senyora|don|do[nñ]a|mr\.?|mrs\.?)\s+", "", value, flags=re.IGNORECASE)
    return value


def add_unique_match(unique: dict[str, str], value: str) -> None:
    """Afegeix un valor evitant duplicats i variants mes llargues del mateix."""

    key = norm_val(value)
    if not key:
        return
    for existing_key, existing_value in list(unique.items()):
        if key == existing_key:
            return
        if key in existing_key and len(existing_key) > len(key) + 3:
            unique.pop(existing_key)
            unique[key] = value
            return
        if existing_key in key and len(key) > len(existing_key) + 3:
            return
    unique[key] = value


def is_likely_name_false_positive(value: str) -> bool:
    """
    Descarta falsos positivos de "Nom i cognoms".

    La regex de nombres tambien puede capturar titulos o filas de tabla como
    "Electronics Wireless Mouse Bluetooth". Si contiene vocabulario de
    documentos, productos o estados, no se cuenta como nombre.
    """

    words = re.split(r"\s+", value.strip())
    relevant_words = [
        word for word in words
        if word.lower() not in {"de", "del", "la", "les", "los", "las", "dels", "i", "y"}
    ]
    if len(relevant_words) < 2:
        return True

    text = f" {norm_val(value)} "
    non_person_terms = {
        "address", "available", "bluetooth", "bottle", "card", "category",
        "client", "description", "document", "electronics", "email", "fake",
        "holder", "information", "item", "kitchen", "mouse", "notebook",
        "office", "payment", "phone", "sports", "status", "stock",
        "synthetic", "test", "this", "water", "wireless", "yoga", "customer",
        "invoice", "report", "confidential", "license", "plate", "street",
        "road", "avenue", "drive", "lane",
        "adreca", "adreça", "categoria", "correu", "descripcio",
        "descripció", "disponible", "estat", "telefon", "telèfon",
        "document", "factura", "informe", "matricula", "matrícula", "carrer",
        "avinguda", "passeig", "plaça", "placa", "rambla",
        "direccion", "dirección", "telefono", "teléfono", "correo",
        "electronico", "electrónico", "disponible", "calle", "avenida",
        "paseo", "plaza",
        "empresa", "societat", "sociedad", "company", "entitat", "entidad",
        "ajuntament", "agencia", "agència", "administracio", "administració",
        "tributaria", "tributària", "estatal", "serveis", "servicios",
        "tecnics", "tècnics", "tecnicos", "técnicos", "xarxes", "redes",
        "telecomunicacions", "telecomunicaciones", "alternatives",
        "alternativas", "valor", "afegit", "añadido", "seguretat",
        "seguridad", "social", "activitats", "actividades", "economiques",
        "econòmiques", "economicas", "económicas", "prevencio", "prevenció",
        "prevencion", "prevención", "riscos", "riesgos", "laborals",
        "laborales", "departament", "ministeri", "ministerio", "institut",
        "instituto", "responsabilitat", "responsabilidad", "civil",
    }
    return any(f" {term.lower()} " in text for term in non_person_terms)


def is_likely_org_false_positive(value: str) -> bool:
    """Descarta fragments administratius que el NER suele marcar como ORG."""

    clean = norm_val(value).strip(" .,:;()-")
    if len(clean) < 6 or clean.endswith((" de", " d", " del", " dels")):
        return True
    words = clean.split()
    if len(words) == 1:
        return True

    false_terms = {
        "administracio", "administració", "administracion", "administración",
        "agencia estatal", "agència estatal", "administracio tributaria",
        "administració tributaria", "administracion tributaria",
        "administración tributaria", "tresoreria general", "tesoreria general",
        "seguretat social", "seguridad social", "serveis tecnics",
        "serveis tècnics", "servicios tecnicos", "servicios técnicos",
        "policia", "responsabilitat civil", "responsabilidad civil",
        "valor afegit", "valor añadido", "activitats economiques",
        "activitats econòmiques", "actividades economicas",
        "actividades económicas", "prevencio de riscos laborals",
        "prevenció de riscos laborals", "prevencion de riesgos laborales",
        "prevención de riesgos laborales", "article", "articulo", "artículo",
        "text legal", "mateix text legal", "d'acord", "d’acord",
    }
    if any(term in clean for term in false_terms):
        return True
    if len(words) > 8 and not re.search(ORG_SUFFIX, value, re.IGNORECASE):
        return True
    return False


def is_likely_company_or_org(value: str) -> bool:
    """Acepta empresas claras y evita organismos/frases demasiado genericas."""

    if is_likely_org_false_positive(value):
        return False
    if re.search(ORG_SUFFIX, value, re.IGNORECASE):
        return True

    clean = norm_val(value)
    words = clean.split()
    if len(words) >= 3 and any(term in clean for term in ("xarxes", "telecomunicacions", "telecomunicaciones")):
        return True
    return False


def merge_findings(findings: list[Finding], extra: Iterable[Finding]) -> list[Finding]:
    """Une resultados de regex y NER sin duplicar valores normalizados."""

    by_type: dict[str, dict[str, str]] = {}
    for finding in findings:
        values: dict[str, str] = {}
        for match in finding.matches:
            add_unique_match(values, match)
        by_type[finding.type] = values
    for finding in extra:
        values = by_type.setdefault(finding.type, {})
        for match in finding.matches:
            add_unique_match(values, match)
    return [Finding(type_name, list(matches.values())) for type_name, matches in by_type.items() if matches]


def env_enabled(name: str) -> bool:
    """Interpreta variables de entorno booleanas."""

    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def configured_ner_model() -> tuple[str, bool]:
    """
    Devuelve modelo NER y si debe cargarse solo desde cache/local.

    Prioridad:
    1. INSPECTOR_NER_MODEL si se define.
    2. models/wikineural-multilingual-ner local si existe.
    3. Modelo remoto fijo por defecto.
    """

    explicit_model = os.environ.get("INSPECTOR_NER_MODEL", "").strip()
    local_only = env_enabled("INSPECTOR_NER_LOCAL_ONLY")
    if explicit_model:
        return explicit_model, local_only
    if LOCAL_NER_MODEL_DIR.exists():
        return str(LOCAL_NER_MODEL_DIR), True
    return DEFAULT_NER_MODEL, local_only


def require_ner() -> bool:
    """Exigeix NER si s'ha demanat o si hi ha un model local empaquetat."""

    if env_enabled("INSPECTOR_DISABLE_NER"):
        return False
    return env_enabled("INSPECTOR_REQUIRE_NER") or LOCAL_NER_MODEL_DIR.exists()


@lru_cache(maxsize=1)
def get_ner_pipeline() -> Any | None:
    """
    Carga un pipeline NER multilingüe si las dependencias estan disponibles.

    Por defecto usa un modelo multilingüe basado en XLM-RoBERTa. Se puede
    cambiar con INSPECTOR_NER_MODEL o desactivar con INSPECTOR_DISABLE_NER=1.
    """

    global NER_LOAD_ERROR
    NER_LOAD_ERROR = ""

    if env_enabled("INSPECTOR_DISABLE_NER"):
        NER_LOAD_ERROR = "NER desactivat per INSPECTOR_DISABLE_NER"
        return None
    try:
        from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline
    except ImportError as exc:
        NER_LOAD_ERROR = f"Falten dependencies NER: {exc}"
        return None

    model_name, local_only = configured_ner_model()
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=local_only)
        model = AutoModelForTokenClassification.from_pretrained(model_name, local_files_only=local_only)
        return pipeline(
            "token-classification",
            model=model,
            tokenizer=tokenizer,
            aggregation_strategy="simple",
        )
    except Exception as exc:
        NER_LOAD_ERROR = f"NER no disponible amb model {model_name!r}: {exc}"
        print(f"Avis: {NER_LOAD_ERROR}", file=sys.stderr)
        return None


def split_ner_chunks(text: str, chunk_size: int = 1800) -> Iterable[str]:
    """Divide texto largo para no superar el tamano habitual del modelo."""

    current: list[str] = []
    current_len = 0
    for paragraph in re.split(r"(\n{2,})", text[:NER_MAX_TEXT_CHARS]):
        if current_len + len(paragraph) > chunk_size and current:
            yield "".join(current)
            current = []
            current_len = 0
        current.append(paragraph)
        current_len += len(paragraph)
    if current:
        yield "".join(current)


def ner_label(entity: dict[str, Any]) -> str:
    """Normaliza etiquetas BIO/agregadas de distintos modelos NER."""

    raw = str(entity.get("entity_group") or entity.get("entity") or entity.get("label") or "")
    return raw.upper().removeprefix("B-").removeprefix("I-")


def scan_ner_entities(text: str, strict: bool) -> list[Finding]:
    """Detecta personas y organizaciones con NER multilingüe."""

    ner = get_ner_pipeline()
    if ner is None:
        if require_ner():
            return [Finding("NER no disponible", [NER_LOAD_ERROR or "No s'ha pogut carregar el model NER"])]
        return []

    persons: dict[str, str] = {}
    orgs: dict[str, str] = {}
    lower_text = text.lower()
    has_person_context = any(ctx.lower() in lower_text for ctx in PERSON_CONTEXT)

    for chunk in split_ner_chunks(text):
        try:
            entities = ner(chunk)
        except Exception as exc:
            print(f"Avis: error executant NER ({exc})", file=sys.stderr)
            return []

        for entity in entities:
            label = ner_label(entity)
            if float(entity.get("score") or 0.0) < NER_MIN_SCORE:
                continue
            value = str(entity.get("word") or "").replace("##", "").strip()
            value = re.sub(r"\s+", " ", value)
            if not value:
                continue

            if label in {"PER", "PERSON"}:
                value = clean_match_value("Nom i cognoms", value)
                if is_likely_name_false_positive(value):
                    continue
                if not strict and not has_person_context and len(value.split()) < 2:
                    continue
                persons.setdefault(norm_val(value), value)
            elif label in {"ORG", "ORGANIZATION"}:
                if not is_likely_company_or_org(value):
                    continue
                orgs.setdefault(norm_val(value), value)

    findings: list[Finding] = []
    if persons:
        findings.append(Finding("Nom i cognoms", list(persons.values())))
    if orgs:
        findings.append(Finding("Empresa / organisme", list(orgs.values())))
    return findings


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


def extract_pdf_with_pypdf(path: Path) -> str:
    """Extrae texto con pypdf cuando esta disponible."""

    try:
        from pypdf import PdfReader
    except ImportError:
        return ""

    try:
        reader = PdfReader(str(path))
        pages: list[str] = []
        for page in reader.pages:
            page_text = page.extract_text() or ""
            if page_text.strip():
                pages.append(page_text.strip())
        return "\n".join(pages)
    except Exception as exc:
        print(f"Avis: pypdf no ha pogut extreure text de {path.name} ({exc})", file=sys.stderr)
        return ""


def extract_pdf_builtin(path: Path) -> str:
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
            text.append("\n")

        offset = end_pos + len(b"endstream")

    return "\n".join(part.strip() for part in text if part.strip())


def extract_pdf(path: Path) -> str:
    """
    Extrae texto de PDF usando pypdf como extractor principal.

    El extractor integrado queda como fallback para entornos sin dependencias.
    """

    return extract_pdf_with_pypdf(path) or extract_pdf_builtin(path)


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
    normalized_text = re.sub(r"[ \t\r\f\v]*\n[ \t\r\f\v]*", " ", text)
    scan_variants = [text]
    if normalized_text != text:
        scan_variants.append(normalized_text)

    for type_name, pattern in get_patterns().items():
        matches = [
            match
            for scan_variant in scan_variants
            for match in pattern.regex.finditer(scan_variant)
        ]
        if not matches:
            continue

        if not pattern.always and not strict:
            if not any(ctx.lower() in lower_text for ctx in pattern.ctx):
                continue

        unique: dict[str, str] = {}
        for match in matches:
            captured = next((group for group in match.groups() if group), match.group(0)) if match.lastindex else match.group(0)
            original = clean_match_value(type_name, captured)
            if type_name == "Matricula vehicle" and norm_val(original).endswith(" csv"):
                continue
            if type_name == "Empresa / organisme" and not is_likely_company_or_org(original):
                continue
            if type_name == "Nom i cognoms" and is_likely_name_false_positive(original):
                continue
            add_unique_match(unique, original)

        if unique:
            output_type = "Adreca postal" if type_name in {"Adreca postal etiquetada", "Adreca postal contextual"} else type_name
            findings.append(Finding(output_type, list(unique.values())))

    return merge_findings(findings, scan_ner_entities(text, strict))


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


def scan_upload_payload(body: bytes, content_type: str, strict: bool, max_size: int, filename: str = "") -> list[ScanResult]:
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
        fallback_name = filename or ("upload.pdf" if "pdf" in content_type.lower() else "upload.bin")
        parts = [(fallback_name, body)]
    return [scan_bytes(payload, filename, strict) for filename, payload in parts]


def analyze_upload(filename: str, content_type: str, body: bytes, strict: bool, max_size: int) -> tuple[bool, str, list[ScanResult]]:
    """Aplica bloqueig basic i el detector de dades sensibles a un upload."""

    safe_name = Path(filename.replace("\\", "/")).name if filename else ""
    if len(body) > max_size:
        result = ScanResult(
            Path(safe_name or "upload.bin"),
            safe_name or "upload.bin",
            len(body),
            Path(safe_name).suffix.lower().lstrip(".") if safe_name else "bin",
            status="sensitive",
            message=f"Mida excessiva: {len(body)} bytes",
            findings=[Finding("Mida maxima", [f"{len(body)} bytes"])],
            total=1,
        )
        return False, result.message, [result]

    if safe_name:
        _, ext = os.path.splitext(safe_name.lower())
        if ext in BLOCKED_EXTENSIONS:
            result = ScanResult(
                Path(safe_name),
                safe_name,
                len(body),
                ext.lstrip("."),
                status="sensitive",
                message=f"Extensio bloquejada: {ext}",
                findings=[Finding("Extensio bloquejada", [ext])],
                total=1,
            )
            return False, result.message, [result]

    mime = content_type.split(";", 1)[0].strip().lower()
    if mime in BLOCKED_MIME_TYPES:
        result = ScanResult(
            Path(safe_name or "upload.bin"),
            safe_name or "upload.bin",
            len(body),
            Path(safe_name).suffix.lower().lstrip(".") if safe_name else "bin",
            status="sensitive",
            message=f"Tipus MIME bloquejat: {mime}",
            findings=[Finding("Tipus MIME bloquejat", [mime])],
            total=1,
        )
        return False, result.message, [result]

    if len(body) >= 4:
        blocked_magic = ""
        if body[:2] == b"MZ":
            blocked_magic = "Executable Windows detectat (magic bytes MZ)"
        elif body[:4] == b"\x7fELF":
            blocked_magic = "Executable Linux detectat (magic bytes ELF)"
        elif body[:2] == b"#!" and b"sh" in body[:32]:
            blocked_magic = "Script de shell detectat (shebang #!)"
        if blocked_magic:
            result = ScanResult(
                Path(safe_name or "upload.bin"),
                safe_name or "upload.bin",
                len(body),
                Path(safe_name).suffix.lower().lstrip(".") if safe_name else "bin",
                status="sensitive",
                message=blocked_magic,
                findings=[Finding("Fitxer executable", [blocked_magic])],
                total=1,
            )
            return False, blocked_magic, [result]

    results = scan_upload_payload(body, content_type, strict, max_size, safe_name)
    if results_are_sensitive(results):
        reasons = []
        for result in results:
            if result.status == "error" and result.message:
                reasons.append(result.message)
            if result.status == "sensitive" and result.findings:
                reasons.extend(finding.type for finding in result.findings)
        reason = "Dades sensibles detectades"
        if reasons:
            reason = "; ".join(dict.fromkeys(reasons[:6]))
        return False, reason, results

    return True, "OK", results


def results_are_sensitive(results: list[ScanResult]) -> bool:
    """Indica si ICAP ha de bloquejar per sensibilitat o inspeccio fallida."""

    return any(result.status in {"sensitive", "error"} for result in results)


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


def log_icap_results(results: list[ScanResult], allowed: bool) -> None:
    """Guarda un informe curt de cada peticio ICAP analitzada."""

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    status = "allowed" if allowed else "blocked"
    output = LOG_DIR / f"icap_{status}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.txt"
    output.write_text(generate_txt(results, "ICAP upload", 0), encoding="utf-8")


def read_headers(rfile: object) -> dict[bytes, bytes]:
    """Llegeix capcaleres ICAP/HTTP des d'un StreamRequestHandler."""

    headers: dict[bytes, bytes] = {}
    while True:
        line = rfile.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        if b":" in line:
            key, _, value = line.partition(b":")
            headers[key.strip().lower()] = value.strip()
    return headers


def read_chunked(rfile: object, max_bytes: int) -> bytes:
    """Llegeix un cos chunked ICAP fins al final o fins al maxim."""

    body = bytearray()
    while True:
        size_line = rfile.readline().strip()
        if not size_line:
            break
        try:
            chunk_size = int(size_line.split(b";", 1)[0], 16)
        except ValueError:
            break
        if chunk_size == 0:
            rfile.readline()
            break
        chunk = rfile.read(chunk_size)
        rfile.readline()
        body.extend(chunk)
        if len(body) >= max_bytes:
            break
    return bytes(body)


def extract_filename_from_url(url: str) -> str:
    """Extreu un nom de fitxer de la URL sense confondre dominis amb fitxers."""

    match = re.search(r"[?&](?:filename|name)=([^&/]+)", url, re.IGNORECASE)
    if match:
        name = urllib.parse.unquote(match.group(1))
        if "." in name and not name.replace(".", "").isdigit():
            return Path(name.replace("\\", "/")).name

    match = re.search(r"/root:/([^:/]+\.[a-zA-Z0-9]+)(?::/|$)", url)
    if match:
        return Path(urllib.parse.unquote(match.group(1)).replace("\\", "/")).name

    path = url.split("?", 1)[0].rstrip("/")
    segment = urllib.parse.unquote(path.split("/")[-1])
    if "." in segment and not re.match(r"^\d+\.\d+\.\d+\.\d+", segment):
        _, ext = os.path.splitext(segment.lower())
        if ext in BLOCKED_EXTENSIONS or len(ext) <= 5:
            return Path(segment.replace("\\", "/")).name
    return ""


def extract_filename_from_headers(headers: dict[bytes, bytes]) -> str:
    """Extreu filename de Content-Disposition si hi es."""

    disposition = headers.get(b"content-disposition", b"").decode("latin-1", errors="replace")
    match = re.search(r"filename\*=([^;\r\n]+)", disposition, re.IGNORECASE)
    if match:
        value = match.group(1).strip().strip("\"'")
        if "''" in value:
            value = value.split("''", 1)[1]
        return Path(urllib.parse.unquote(value).replace("\\", "/")).name

    match = re.search(r"filename=[\"']?([^\"';\r\n]+)[\"']?", disposition, re.IGNORECASE)
    if match:
        return Path(urllib.parse.unquote(match.group(1).strip()).replace("\\", "/")).name
    return ""


def extract_filename_from_multipart(body: bytes, content_type: str) -> str:
    """Busca un filename dins d'un multipart/form-data."""

    if "multipart" not in content_type.lower():
        return ""
    try:
        text = body[:8192].decode("latin-1", errors="replace")
    except Exception:
        return ""
    match = re.search(r'filename="([^"]+)"', text, re.IGNORECASE)
    if match:
        return Path(urllib.parse.unquote(match.group(1)).replace("\\", "/")).name
    return ""


def send_icap_raw(wfile: object, status: bytes) -> None:
    """Envia una resposta ICAP simple sense cos encapsulat."""

    wfile.write(b"ICAP/1.0 " + status + b"\r\n")
    wfile.write(b"Server: " + ICAP_SERVER_NAME + b"\r\n")
    wfile.write(b'ISTag: "SensitiveDataInspector-3.1"\r\n')
    wfile.write(b"Encapsulated: null-body=0\r\n\r\n")
    wfile.flush()


def send_icap_options(wfile: object) -> None:
    """Resposta OPTIONS per al servei REQMOD."""

    wfile.write(b"ICAP/1.0 200 OK\r\n")
    wfile.write(b"Methods: REQMOD\r\n")
    wfile.write(b"Service: Sensitive Data Inspector ICAP\r\n")
    wfile.write(b"Server: " + ICAP_SERVER_NAME + b"\r\n")
    wfile.write(b'ISTag: "SensitiveDataInspector-3.1"\r\n')
    wfile.write(b"Allow: 204\r\n")
    wfile.write(b"Preview: 0\r\n")
    wfile.write(b"Transfer-Complete: *\r\n")
    wfile.write(b"Encapsulated: null-body=0\r\n\r\n")
    wfile.flush()


def send_icap_block(wfile: object, filename: str, reason: str) -> None:
    """Retorna un HTTP 403 encapsulat en una resposta ICAP 200."""

    safe_filename = filename or "upload"
    page = (
        "<html><body><h1>Pujada bloquejada</h1>"
        f"<p>Fitxer: {safe_filename}</p>"
        f"<p>Motiu: {reason}</p></body></html>"
    ).encode("utf-8", errors="replace")
    response_headers = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: " + str(len(page)).encode("ascii") + b"\r\n\r\n"
    )
    enc_value = b"res-hdr=0, res-body=" + str(len(response_headers)).encode("ascii")
    wfile.write(b"ICAP/1.0 200 OK\r\n")
    wfile.write(b"Server: " + ICAP_SERVER_NAME + b"\r\n")
    wfile.write(b'ISTag: "SensitiveDataInspector-3.1"\r\n')
    wfile.write(b"Encapsulated: " + enc_value + b"\r\n\r\n")
    wfile.write(response_headers)
    wfile.write(hex(len(page))[2:].encode("ascii") + b"\r\n")
    wfile.write(page + b"\r\n0\r\n\r\n")
    wfile.flush()


def install_ner_model() -> int:
    """Descarrega el model NER fix al directori local models/."""

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("ERROR: falta huggingface_hub. Instal-la amb: python -m pip install huggingface_hub", file=sys.stderr)
        return 2

    LOCAL_NER_MODEL_DIR.parent.mkdir(parents=True, exist_ok=True)
    print(f"Descarregant model NER a: {LOCAL_NER_MODEL_DIR}")
    snapshot_download(
        repo_id=DEFAULT_NER_MODEL,
        local_dir=str(LOCAL_NER_MODEL_DIR),
        local_dir_use_symlinks=False,
    )
    print("Model NER local preparat.")
    return 0


def run_icap_server(host: str, port: int, strict: bool, max_size: int) -> int:
    """Arranca el servidor ICAP REQMOD compatible amb OPNsense."""

    class ScanHandler(socketserver.StreamRequestHandler):
        """Handler ICAP manual que reutilitza la logica DLP de l'inspector."""

        def handle(self) -> None:
            try:
                while True:
                    request_line = self.rfile.readline()
                    if not request_line:
                        break
                    request_line = request_line.strip()
                    if not request_line:
                        continue

                    parts = request_line.split(b" ")
                    if len(parts) < 2:
                        break
                    method = parts[0].upper()
                    icap_headers = read_headers(self.rfile)

                    if method == b"OPTIONS":
                        send_icap_options(self.wfile)
                    elif method == b"REQMOD":
                        self.handle_reqmod(icap_headers)
                    else:
                        send_icap_raw(self.wfile, b"400 Bad Request")
                    break
            except Exception as exc:
                print(f"ERROR ICAP: {exc}", file=sys.stderr)

        def handle_reqmod(self, icap_headers: dict[bytes, bytes]) -> None:
            client_ip = icap_headers.get(b"x-client-ip", b"unknown").decode("latin-1", errors="replace")
            encapsulated = icap_headers.get(b"encapsulated", b"").decode("latin-1", errors="replace").lower()
            has_req_hdr = "req-hdr" in encapsulated
            has_req_body = "req-body" in encapsulated

            http_method = ""
            http_url = ""
            http_headers: dict[bytes, bytes] = {}

            if has_req_hdr:
                req_line = self.rfile.readline().decode("latin-1", errors="replace").strip()
                parts = req_line.split(" ")
                if len(parts) >= 2:
                    http_method = parts[0].upper()
                    http_url = parts[1]
                http_headers = read_headers(self.rfile)

            body = read_chunked(self.rfile, max_size) if has_req_body else b""
            if http_method not in UPLOAD_METHODS or not body:
                send_icap_raw(self.wfile, b"204 No Modifications Needed")
                return

            content_type = http_headers.get(b"content-type", b"").decode("latin-1", errors="replace")
            filename = extract_filename_from_url(http_url) or extract_filename_from_headers(http_headers)
            if not filename:
                filename = extract_filename_from_multipart(body, content_type)

            allowed, reason, results = analyze_upload(filename, content_type, body, strict, max_size)
            if allowed:
                send_icap_raw(self.wfile, b"204 No Modifications Needed")
                return

            log_icap_results(results, allowed=False)
            print(
                f"ICAP bloquejat IP={client_ip} metode={http_method!r} "
                f"fitxer={filename!r} mida={len(body)} motiu={reason}",
                file=sys.stderr,
            )
            send_icap_block(self.wfile, filename, reason)

    class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
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
    parser.add_argument("--install-ner-model", action="store_true", help="Descarrega el model NER fix a models/")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Punto de entrada principal."""

    start = time.time()
    args = parse_args(argv)

    if args.install_ner_model:
        return install_ner_model()

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
