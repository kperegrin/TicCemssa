#!/usr/bin/env php
<?php
declare(strict_types=1);
error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE);

/**
 * ═══════════════════════════════════════════════════════════════
 *  Inspector de Dades Sensibles — v3.0
 *  Requeriments: PHP 8.1+ amb extensions: zip, mbstring, zlib, dom, iconv
 *
 *  Llibreries (opcionals però recomanades, via Composer):
 *    composer require smalot/pdfparser          (PDF robust)
 *    composer require phpoffice/phpword         (DOCX/ODT/RTF)
 *    composer require phpoffice/phpspreadsheet  (XLSX/ODS/XLS/CSV)
 *
 *  Si les llibreries Composer no estan disponibles, l'script fa
 *  servir els extractors integrats com a fallback (menys precisos).
 *
 *  Formats suportats: TXT, CSV, JSON, XML, LOG, MD, YAML, INI
 *                     PDF, DOCX, XLSX, ODS, ODT, RTF
 *  Formats ignorats:  ZIP, RAR, 7Z, TAR, GZ i fitxers binaris
 * ═══════════════════════════════════════════════════════════════
 */

// ── Autoloader Composer (si existeix) ───────────────────────────
// Busca composer autoload en ubicacions habituals
foreach ([
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../../vendor/autoload.php',
] as $autoload) {
    if (file_exists($autoload)) { require_once $autoload; break; }
}

// mbstring polyfills — activos solo si la extensión no está cargada
if (!function_exists('mb_strlen'))           { function mb_strlen($s, $e=null): int    { return strlen($s); } }
if (!function_exists('mb_substr'))           { function mb_substr($s,$st,$ln=null,$e=null): string { return $ln===null ? substr($s,$st) : substr($s,$st,$ln); } }
if (!function_exists('mb_strtolower'))       { function mb_strtolower($s,$e=null): string          { return strtolower($s); } }
if (!function_exists('mb_stripos'))          { function mb_stripos($h,$n,$o=0,$e=null)              { return stripos($h,$n,$o); } }
if (!function_exists('mb_detect_encoding')) { function mb_detect_encoding($s,$l=null,$strict=false){ return 'UTF-8'; } }
if (!function_exists('mb_convert_encoding')){ function mb_convert_encoding($s,$to,$from=null): string { return $s; } }
if (!function_exists('mb_check_encoding'))  { function mb_check_encoding($s,$e=null): bool         { return true; } }

define('APP_VERSION', '3.0.0');
define('LOG_DIR',     __DIR__ . '/logs');

/*
 * Flujo general del script:
 * 1. Recibe una lista de ficheros o un directorio desde la CLI.
 * 2. Extrae texto de cada fichero segun su formato.
 * 3. Aplica patrones de datos sensibles sobre el texto extraido.
 * 4. Genera un informe TXT o PDF y devuelve codigo 1 si hay sensibilidad.
 */

// ── Extensions suportades (mai ZIP) ─────────────────────────────
const SUPPORTED_EXT = [
    'txt','csv','log','md','ini','json','xml','yaml','yml',
    'pdf','docx','xlsx','xls','ods','odt','rtf',
    'sql','conf','cfg','env','properties',
];
const SKIP_EXT = [
    'zip','rar','7z','tar','gz','bz2','xz',
    'exe','dll','so','bin','o','class',
    'jpg','jpeg','png','gif','bmp','webp','svg','ico',
    'mp3','mp4','avi','mov','wav','ogg',
    'ttf','otf','woff','woff2',
];

// ── Patrons de dades sensibles ───────────────────────────────────
/*
 * Cada patron define:
 * - regex: expresion regular que localiza el dato.
 * - ctx: palabras de contexto que refuerzan patrones ambiguos.
 * - always: si true, el patron cuenta aunque no haya contexto.
 * - mask: funcion preparada para censurar el valor si se usa en otra salida.
 */
function getPatterns(): array {
return [
    'DNI / NIE' => [
        'regex'  => '/\b(?:[0-9]{8}[A-Za-z]|[XYZxyz][0-9]{7}[A-Za-z])\b/',
        'ctx'    => ['dni','nif','nie','document','identif'],
        'always' => true,
        'mask'   => fn($v) => substr($v,0,3) . str_repeat('*', strlen($v)-4) . substr($v,-1),
    ],
    'Telèfon' => [
        'regex'  => '/(?<!\d)(?:\+34[\s.\-]?|0034[\s.\-]?)?[6789]\d{2}[\s.\-]?\d{3}[\s.\-]?\d{3}(?!\d)/',
        'ctx'    => ['tel','fax','movil','phone','contacte','phone'],
        'always' => true,
        'mask'   => fn($v) => preg_replace('/\d(?=\d{3})/', '*', $v),
    ],
    'Correu electrònic' => [
        'regex'  => '/\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/',
        'ctx'    => ['email','correu','mail'],
        'always' => true,
        'mask'   => fn($v) => preg_replace_callback('/^(.{2}).*(@.*)$/', fn($m) => $m[1].str_repeat('*',6).$m[2], $v),
    ],
    'Targeta bancària' => [
        'regex'  => '/\b(?:4[\d]{3}(?:[\s\-]?[\d]{4}){3}|5[1-5][\d]{2}(?:[\s\-]?[\d]{4}){3}|3[47][\d]{2}(?:[\s\-]?[\d]{6})(?:[\s\-]?[\d]{5})|3(?:0[0-5]|[68][\d])[\d]{2}(?:[\s\-]?[\d]{6})(?:[\s\-]?[\d]{4})|6(?:011|5[\d]{2})(?:[\s\-]?[\d]{4}){3})/',
        'ctx'    => ['targeta','tarjeta','card','visa','mastercard','card holder','card number'],
        'always' => true,
        'mask'   => fn($v) => preg_replace('/\d(?=[\d\s\-]{5})/', '*', $v),
    ],
    'CVV' => [
        'regex'  => '/\b(?:cvv|cvc|csv|security code)[\s:]*(\d{3,4})\b/i',
        'ctx'    => ['cvv','cvc','card','targeta'],
        'always' => true,
        'mask'   => fn($v) => preg_replace('/\d/', '*', $v),
    ],
    'IBAN' => [
        'regex'  => '/\b[A-Z]{2}[0-9]{2}(?:\s?[0-9]{4}){4,6}(?:\s?[0-9]{1,4})?\b/',
        'ctx'    => ['iban','compte','cuenta','bank','transfer'],
        'always' => true,
        'mask'   => fn($v) => substr($v,0,4) . str_repeat('*', strlen($v)-8) . substr($v,-4),
    ],
    'Contrasenya' => [
        'regex'  => '/(?:password|passwd|contrasenya|contrase[nñ]a|pwd|pass|secret|clau|clave|token)\s*[=:]\s*\S+/i',
        'ctx'    => ['password','secret','clau','clave','token'],
        'always' => true,
        'mask'   => fn($v) => preg_replace('/=.*$/', '=***', $v),
    ],
    'Nom i cognoms' => [
        // Requereix Nom + 2 cognoms (mínim 3 paraules tipus "Joan Garcia Pérez").
        // Així un fitxer amb només "Joan Garcia" no es marca com a sensible.
        'regex'  => '/\b([A-ZÀ-Ÿ][a-zà-ÿ]{1,20}(?:\s+[A-ZÀ-Ÿ][a-zà-ÿ]{1,20}){2,3})\b/u',
        'ctx'    => ['name','nombre','nom','cognoms','apellido','titular','client','clienta','signat'],
        'always' => false,
        'mask'   => fn($v) => preg_replace('/(?<=\S)\S/u', '*', $v),
    ],
    'Adreça postal' => [
        // ── Cobreix els formats habituals en català i castellà ───────
        //
        // Tipus de via suportats (complets i abreviats):
        //   CAT: Carrer/C.  Avinguda/Av./Avda.  Passeig/Pg.
        //        Plaça/Pl.  Ronda  Travessera/Trav.  Camí/Camino
        //        Rambla  Rbla.  Gran Via  Passatge/Ptge.
        //   CAST: Calle/C/  Avenida/Av./Avda.  Paseo/P.º
        //        Plaza/Pza./Plza.  Ronda  Callejón/Callej.
        //        Travesía/Trav.  Bulevar/Blv.  Urbanización/Urb.
        //        Polígono/Pol.  Glorieta/Glta.  Vía/Via
        //
        // Estructura capturada:
        //   <TipusVia> [de/del/de la/dels/de las/de los/d'] <Nom>, <Núm>
        //   [, <pis> [<porta>]] [, Esc. X] [— <CP> <Municipi>]
        //
        // Exemples vàlids:
        //   Carrer de la Llibertat, 12, 3r 2a
        //   C/ Major, 5 Baixos
        //   Calle del Pez, 7, 1º Izq
        //   Avinguda Catalunya, 100, 4t 1a — 08003 Barcelona
        //   Paseo de Gracia, 43
        //   Pl. de la Vila, 3, 1r — 17001 Girona
        //   Pg. Marítim, 22, 3r 2a
        //   Urb. Can Roca, 15
        //   Gran Via de les Corts Catalanes, 585
        //
        'regex'  => '/(?:Gran\s+Via|Avinguda|Avenida|Avda\.|Avda|Av\.|Av|Travessera|Traves[i\x{ED}]a|Trav\.|Passatge|Ptge\.|Passeig|Pg\.|Paseo|P\.º|Carrer|Calle|Callej\.|Callejon|Cal|Bulevar|Blv\.|Urbanitzaci[o\x{F3}]|Urbanizaci[o\x{F3}]n|Urb\.|Urb|Pol[i\x{ED}]gonos?|Pol\.|Glorieta|Glta\.|Rambla|Rbla\.|Ronda|Cam[i\x{ED}]|Camino|Cami|Pla[c\x{E7}]a|Plaza|Pza\.|Plza\.|Pl\.|Via|C\/)(?:[^\S\n]+(?:de\s+la|de\s+les|de\s+los|de\s+las|dels|del|de|d\x27))?[^\S\n]+[A-Za-z\x{C0}-\x{FF}][A-Za-z\x{C0}-\x{FF}\ \-]{1,50}[,\ ]+\d{1,5}(?:[,\ ]+(?:\d{1,3}[rRtT\x{E8}\x{E9}aA\x{B0}\x{BA}](?:\ *[0-9a-zA-Z]{1,3})?|[Bb]aixos|[Bb]ajos|[Ee]ntresol|[Pp]rincipal|[Pp]ral\.?|[\x{C1}\x{E1}]tico|[\x{C0}\x{E0}]tic|[Ll]ocal|[Ee]sc\.?\ *[A-Z]))?(?:[\ ,\-\x{2014}]+(?:CP[\ .:]*)?[0-5]\d{4}(?:\ +[A-Z\x{C0}-\x{FF}][A-Za-z\x{C0}-\x{FF}\ \-]{2,30})?)?/u',
        'ctx'    => [
            // Català
            'adreça','adreca','domicili','carrer','avinguda','passeig',
            'plaça','placa','rambla','camí','cami','passatge',
            // Castellà
            'dirección','direccion','domicilio','calle','avenida',
            'paseo','plaza','ronda','bulevar','urbanizacion','poligono',
            // Genèric
            'adress','address','via','cp','codi postal','codigo postal',
        ],
        'always' => true,
        'mask'   => fn($v) => preg_replace('/\d/', '*', $v),
    ],
    'Data de naixement' => [
        'regex'  => '/\b(?:(?:19|20)\d{2}[\-\/.](?:0?[1-9]|1[0-2])[\-\/.](?:0?[1-9]|[12]\d|3[01])|(?:0?[1-9]|[12]\d|3[01])[\-\/.](?:0?[1-9]|1[0-2])[\-\/.](?:19|20)\d{2})\b/',
        'ctx'    => ['naix','naci','born','birthday','dob','data','fecha','dob'],
        'always' => true,
        'mask'   => fn($v) => preg_replace('/\d{2}(?=\d)/', '**', $v),
    ],
    'Adreça IP' => [
        'regex'  => '/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/',
        'ctx'    => ['ip','host','server','servidor','xarxa'],
        'always' => false,
        'mask'   => fn($v) => preg_replace('/\.\d+$/', '.***', $v),
    ],
    'Número SS' => [
        'regex'  => '/\b\d{2}[\s\/\-]?\d{8}[\s\/\-]?\d{2}\b/',
        'ctx'    => ['seguretat social','seguridad social','nss'],
        'always' => false,
        'mask'   => fn($v) => substr($v,0,2) . str_repeat('*', strlen($v)-4) . substr($v,-2),
    ],
];
}

// ════════════════════════════════════════════════════════════════
//  EXTRACTORS DE TEXT — 100% PHP pur
// ════════════════════════════════════════════════════════════════

/**
 * Decodifica streams PDF con filtro ASCII85Decode.
 * Algunos PDF guardan el texto comprimido/codificado dentro de streams.
 */
function ascii85Decode(string $data): string {
    $data = preg_replace('/\s/', '', $data);
    if (str_ends_with($data, '~>')) $data = substr($data, 0, -2);
    $out = '';
    $i = 0; $len = strlen($data);
    while ($i < $len) {
        if ($data[$i] === 'z') { $out .= "\x00\x00\x00\x00"; $i++; continue; }
        $chunk = substr($data, $i, 5);
        $pad = 5 - strlen($chunk);
        $chunk = str_pad($chunk, 5, 'u');
        $n = 0;
        for ($j = 0; $j < 5; $j++) $n = $n * 85 + (ord($chunk[$j]) - 33);
        $bytes = pack('N', $n);
        $out .= substr($bytes, 0, 4 - $pad);
        $i += 5;
    }
    return $out;
}

/**
 * Extrae texto de un PDF.
 * Primero intenta usar smalot/pdfparser si esta instalado; si no, usa el
 * extractor manual de abajo para no depender de Composer.
 */
function extractPdf(string $path): string {
    // Preferent: smalot/pdfparser (composer require smalot/pdfparser)
    if (class_exists('\Smalot\PdfParser\Parser')) {
        try {
            $parser = new \Smalot\PdfParser\Parser();
            $pdf    = $parser->parseFile($path);
            $text   = $pdf->getText();
            if (trim($text) !== '') return $text;
        } catch (\Throwable $e) {
            // continua amb fallback
        }
    }

    // Fallback: extractor manual integrat
    return extractPdfFallback($path);
}

/**
 * Extractor PDF manual.
 * Recorre streams, aplica filtros comunes y busca operadores de texto Tj/TJ.
 * No entiende todos los PDF posibles, pero cubre documentos simples.
 */
function extractPdfFallback(string $path): string {
    $raw = @file_get_contents($path);
    if (!$raw) return '';

    $text = '';
    $off  = 0;
    $len  = strlen($raw);

    while ($off < $len) {
        $sPos = strpos($raw, 'stream', $off);
        if ($sPos === false) break;
        $ePos = strpos($raw, 'endstream', $sPos + 6);
        if ($ePos === false) break;

        // Read filter declarations from the object dict before this stream
        $dictRegion = substr($raw, max(0, $sPos - 512), 512);
        preg_match('/\/Filter\s*(\[.*?\]|\/\S+)/s', $dictRegion, $fm);
        $filterStr = $fm[1] ?? '';
        $filters = [];
        preg_match_all('/\/([A-Za-z0-9]+(?:Decode)?)/', $filterStr, $fnames);
        foreach ($fnames[1] as $fn) {
            $fn = strtolower($fn);
            if (in_array($fn, ['ascii85decode','flatedecode','lzwdecode','asciihexdecode'])) $filters[] = $fn;
        }

        $ds = $sPos + 6;
        if ($ds < $len && $raw[$ds] === "\r") $ds++;
        if ($ds < $len && $raw[$ds] === "\n") $ds++;
        $blob = substr($raw, $ds, $ePos - $ds);

        // Apply filters in order
        $data = $blob;
        foreach ($filters as $filter) {
            if ($filter === 'ascii85decode') {
                $data = ascii85Decode(rtrim($data));
            } elseif ($filter === 'flatedecode') {
                $dec = @gzuncompress($data);
                if ($dec === false) $dec = @gzinflate(substr($data, 2));
                if ($dec === false) $dec = @gzinflate($data);
                if ($dec !== false) $data = $dec;
            } elseif ($filter === 'asciihexdecode') {
                $data = pack('H*', preg_replace('/\s|>/', '', $data));
            }
        }

        // If no filters detected, try brute-force decompress
        if (empty($filters)) {
            $dec = @gzuncompress($blob);
            if ($dec === false) $dec = @gzinflate(substr($blob, 2));
            if ($dec !== false) $data = $dec;
        }

        // Extract text operators
        if (preg_match_all('/\(([^)\\\\]*(\\\\.[^)\\\\]*)*)\)\s*[Tj\'\"]/s', $data, $m)) {
            foreach ($m[1] as $t) $text .= pdfStr($t) . ' ';
        }
        if (preg_match_all('/\[([^\[\]]*)\]\s*TJ/s', $data, $m)) {
            foreach ($m[1] as $tj) {
                if (preg_match_all('/\(([^)\\\\]*(\\\\.[^)\\\\]*)*)\)/s', $tj, $m2)) {
                    foreach ($m2[1] as $t) $text .= pdfStr($t);
                }
                $text .= ' ';
            }
        }

        $off = $ePos + 9;
    }

    // Fallback: cadenes ASCII del raw (metadata, XMP, etc.)
    if (preg_match_all('/[\x20-\x7E]{6,}/', $raw, $m)) {
        $text .= ' ' . implode(' ', $m[0]);
    }

    return $text;
}
/**
 * Normaliza cadenas escapadas dentro de un PDF a texto UTF-8 legible.
 */
function pdfStr(string $s): string {
    $s = str_replace(['\\n','\\r','\\t','\\(','\\)','\\\\'], ["\n","\r","\t",'(',')',"\\"], $s);
    if (!mb_check_encoding($s, 'UTF-8')) {
        $s = mb_convert_encoding($s, 'UTF-8', 'ISO-8859-1');
    }
    return $s;
}

/** DOCX: ZIP + word/document.xml + capçaleres/peus */
/**
 * Extrae texto de DOCX.
 * DOCX es un ZIP con XML internos; se intenta PhpWord y despues fallback ZIP.
 */
function extractDocx(string $path): string {
    // Preferent: PhpOffice\PhpWord (composer require phpoffice/phpword)
    if (class_exists('\PhpOffice\PhpWord\IOFactory')) {
        try {
            $phpWord = \PhpOffice\PhpWord\IOFactory::load($path, 'Word2007');
            $text = phpWordToText($phpWord);
            if (trim($text) !== '') return $text;
        } catch (\Throwable $e) {
            // continua amb fallback
        }
    }
    return extractDocxFallback($path);
}

/** Recorre l'estructura PhpWord recursivament per recollir tot el text */
/**
 * Convierte un documento cargado por PhpWord a texto plano.
 */
function phpWordToText($container): string {
    $out = '';
    if (!method_exists($container, 'getSections') && !method_exists($container, 'getElements')) {
        return $out;
    }
    $sections = method_exists($container, 'getSections') ? $container->getSections() : [$container];
    foreach ($sections as $section) {
        $out .= phpWordWalk($section) . "\n";
        // Capçaleres i peus
        if (method_exists($section, 'getHeaders')) {
            foreach ($section->getHeaders() as $h) $out .= phpWordWalk($h) . "\n";
        }
        if (method_exists($section, 'getFooters')) {
            foreach ($section->getFooters() as $f) $out .= phpWordWalk($f) . "\n";
        }
    }
    return $out;
}

/**
 * Recorre recursivamente elementos PhpWord: parrafos, tablas, filas y celdas.
 */
function phpWordWalk($element): string {
    $out = '';
    if (method_exists($element, 'getText')) {
        $t = $element->getText();
        if (is_string($t)) $out .= $t . ' ';
    }
    if (method_exists($element, 'getElements')) {
        foreach ($element->getElements() as $sub) {
            $out .= phpWordWalk($sub) . ' ';
        }
    }
    // Files i cel·les de taules
    if (method_exists($element, 'getRows')) {
        foreach ($element->getRows() as $row) {
            foreach ($row->getCells() as $cell) $out .= phpWordWalk($cell) . ' ';
            $out .= "\n";
        }
    }
    return $out;
}

/**
 * Fallback DOCX sin librerias externas.
 * Lee document.xml, cabeceras y pies, y concatena nodos w:t.
 */
function extractDocxFallback(string $path): string {
    if (!class_exists('ZipArchive')) return '';
    $zip = new ZipArchive();
    if ($zip->open($path) !== true) return '';

    $parts = [];
    $ns    = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';

    foreach (['word/document.xml',
              'word/header1.xml','word/header2.xml','word/header3.xml',
              'word/footer1.xml','word/footer2.xml','word/footer3.xml'] as $entry) {
        $xml = $zip->getFromName($entry);
        if ($xml === false) continue;
        $dom = new DOMDocument();
        @$dom->loadXML($xml);
        $nodes = $dom->getElementsByTagNameNS($ns, 't');
        $chunk = [];
        foreach ($nodes as $n) $chunk[] = $n->textContent;
        $parts[] = implode(' ', $chunk);
    }
    $zip->close();
    return implode("\n", array_filter($parts));
}

/** XLSX: ZIP + xl/sharedStrings.xml + xl/worksheets/sheet*.xml */
/**
 * Extrae texto de XLSX/XLS.
 * Usa PhpSpreadsheet si existe; si no, lee sharedStrings y worksheets.
 */
function extractXlsx(string $path): string {
    // Preferent: PhpSpreadsheet (composer require phpoffice/phpspreadsheet)
    if (class_exists('\PhpOffice\PhpSpreadsheet\IOFactory')) {
        try {
            $reader = \PhpOffice\PhpSpreadsheet\IOFactory::createReaderForFile($path);
            $reader->setReadDataOnly(true);
            $spreadsheet = $reader->load($path);
            $out = [];
            foreach ($spreadsheet->getAllSheets() as $sheet) {
                foreach ($sheet->getRowIterator() as $row) {
                    $cellIter = $row->getCellIterator();
                    $cellIter->setIterateOnlyExistingCells(true);
                    foreach ($cellIter as $cell) {
                        $v = $cell->getValue();
                        if ($v !== null && $v !== '') $out[] = (string)$v;
                    }
                    $out[] = "\n";
                }
            }
            $text = implode(' ', $out);
            if (trim($text) !== '') return $text;
        } catch (\Throwable $e) {
            // continua amb fallback
        }
    }
    return extractXlsxFallback($path);
}

/**
 * Fallback XLSX: resuelve shared strings y valores de las hojas.
 */
function extractXlsxFallback(string $path): string {
    if (!class_exists('ZipArchive')) return '';
    $zip = new ZipArchive();
    if ($zip->open($path) !== true) return '';

    // Shared strings
    $ss = [];
    $ssXml = $zip->getFromName('xl/sharedStrings.xml');
    if ($ssXml) {
        $dom = new DOMDocument();
        @$dom->loadXML($ssXml);
        foreach ($dom->getElementsByTagName('si') as $si) $ss[] = $si->textContent;
    }

    $values = [];
    for ($i = 1; $i <= 30; $i++) {
        $xml = $zip->getFromName("xl/worksheets/sheet{$i}.xml");
        if ($xml === false) break;
        $dom = new DOMDocument();
        @$dom->loadXML($xml);
        foreach ($dom->getElementsByTagName('c') as $cell) {
            $t = $cell->getAttribute('t');
            if ($t === 's') {
                // Shared string index
                $v = $cell->getElementsByTagName('v')->item(0)?->textContent ?? '';
                $values[] = $ss[(int)$v] ?? '';
            } elseif ($t === 'inlineStr') {
                $is = $cell->getElementsByTagName('is')->item(0);
                if ($is) $values[] = $is->textContent;
            } else {
                $v = $cell->getElementsByTagName('v')->item(0)?->textContent ?? '';
                if ($v !== '') $values[] = $v;
            }
        }
    }
    $zip->close();
    return implode(' ', array_filter($values));
}

/** ODS (LibreOffice Calc): ZIP + content.xml */
/**
 * Extrae texto de ODS (LibreOffice Calc).
 */
function extractOds(string $path): string {
    // Preferent: PhpSpreadsheet
    if (class_exists('\PhpOffice\PhpSpreadsheet\IOFactory')) {
        try {
            $reader = \PhpOffice\PhpSpreadsheet\IOFactory::createReader('Ods');
            $reader->setReadDataOnly(true);
            $spreadsheet = $reader->load($path);
            $out = [];
            foreach ($spreadsheet->getAllSheets() as $sheet) {
                foreach ($sheet->getRowIterator() as $row) {
                    foreach ($row->getCellIterator() as $cell) {
                        $v = $cell->getValue();
                        if ($v !== null && $v !== '') $out[] = (string)$v;
                    }
                }
            }
            $text = implode(' ', $out);
            if (trim($text) !== '') return $text;
        } catch (\Throwable $e) {}
    }
    return extractOdsFallback($path);
}

/**
 * Fallback ODS: lee content.xml y concatena celdas con texto.
 */
function extractOdsFallback(string $path): string {
    if (!class_exists('ZipArchive')) return '';
    $zip = new ZipArchive();
    if ($zip->open($path) !== true) return '';
    $xml = $zip->getFromName('content.xml');
    $zip->close();
    if (!$xml) return '';

    $dom = new DOMDocument();
    @$dom->loadXML($xml);
    $ns = 'urn:oasis:names:tc:opendocument:xmlns:table:1.0';
    $out = [];
    foreach ($dom->getElementsByTagNameNS($ns, 'table-cell') as $cell) {
        $v = trim($cell->textContent);
        if ($v !== '') $out[] = $v;
    }
    return implode(' ', $out);
}

/** ODT (LibreOffice Writer): ZIP + content.xml */
/**
 * Extrae texto de ODT (LibreOffice Writer).
 */
function extractOdt(string $path): string {
    // Preferent: PhpWord
    if (class_exists('\PhpOffice\PhpWord\IOFactory')) {
        try {
            $phpWord = \PhpOffice\PhpWord\IOFactory::load($path, 'ODText');
            $text = phpWordToText($phpWord);
            if (trim($text) !== '') return $text;
        } catch (\Throwable $e) {}
    }
    return extractOdtFallback($path);
}

/**
 * Fallback ODT: lee parrafos de content.xml.
 */
function extractOdtFallback(string $path): string {
    if (!class_exists('ZipArchive')) return '';
    $zip = new ZipArchive();
    if ($zip->open($path) !== true) return '';
    $xml = $zip->getFromName('content.xml');
    $zip->close();
    if (!$xml) return '';

    $dom = new DOMDocument();
    @$dom->loadXML($xml);
    $ns = 'urn:oasis:names:tc:opendocument:xmlns:text:1.0';
    $out = [];
    foreach ($dom->getElementsByTagNameNS($ns, 'p') as $p) {
        $v = trim($p->textContent);
        if ($v !== '') $out[] = $v;
    }
    return implode("\n", $out);
}

/** RTF: elimina les seqüències de control */
/**
 * Extrae texto de RTF.
 */
function extractRtf(string $path): string {
    if (class_exists('\PhpOffice\PhpWord\IOFactory')) {
        try {
            $phpWord = \PhpOffice\PhpWord\IOFactory::load($path, 'RTF');
            $text = phpWordToText($phpWord);
            if (trim($text) !== '') return $text;
        } catch (\Throwable $e) {}
    }
    return extractRtfFallback($path);
}

/**
 * Fallback RTF simple: elimina grupos y comandos de control RTF.
 */
function extractRtfFallback(string $path): string {
    $raw = @file_get_contents($path);
    if (!$raw) return '';
    $text = preg_replace('/\{[^{}]*\}/', ' ', $raw) ?? $raw;
    $text = preg_replace('/\\\\[a-z]+[-]?\d*\s?/', ' ', $text) ?? $text;
    $text = preg_replace('/[{}\\\\]/', ' ', $text) ?? $text;
    return $text;
}

/** Text pla: TXT, CSV, JSON, XML, LOG, MD, YAML, INI, SQL, ENV… */
/**
 * Lee formatos de texto plano y normaliza codificacion a UTF-8 si puede.
 */
function extractPlain(string $path): string {
    $raw = @file_get_contents($path);
    if ($raw === false) return '';
    $enc = mb_detect_encoding($raw, ['UTF-8','ISO-8859-1','Windows-1252','UTF-16'], true);
    if ($enc && $enc !== 'UTF-8') $raw = mb_convert_encoding($raw, 'UTF-8', $enc);
    return $raw;
}

/** Dispatcher: tria l'extractor correcte */
/**
 * Dispatcher unico de extraccion.
 * Mantiene aislado el resto del codigo de los detalles de cada formato.
 */
function extractText(string $path): string {
    return match (strtolower(pathinfo($path, PATHINFO_EXTENSION))) {
        'pdf'           => extractPdf($path),
        'docx'          => extractDocx($path),
        'xlsx', 'xls'   => extractXlsx($path),
        'ods'           => extractOds($path),
        'odt'           => extractOdt($path),
        'rtf'           => extractRtf($path),
        default         => extractPlain($path),
    };
}

// ════════════════════════════════════════════════════════════════
//  DETECTOR DE DADES SENSIBLES
// ════════════════════════════════════════════════════════════════

/**
 * Normaliza valores para comparar y deduplicar coincidencias.
 * Ejemplo: "  Juan   Perez " y "juan perez" se consideran el mismo valor.
 */
function normVal(string $v): string {
    return mb_strtolower(trim(preg_replace('/\s+/', ' ', $v) ?? $v));
}

/**
 * Filtro especifico para "Nom i cognoms".
 *
 * La regex de nombres busca 3-4 palabras con mayuscula inicial. Eso tambien
 * puede coincidir con titulos, cabeceras o filas de catalogo:
 * "Electronics Wireless Mouse Bluetooth", "Sensitive Test Document This", etc.
 * Este filtro descarta candidatos con palabras habituales de documentos,
 * tablas, productos o estados.
 */
function isLikelyNameFalsePositive(string $value): bool {
    $words = preg_split('/\s+/u', trim($value), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    if (count($words) < 3) return true;

    $text = ' ' . normVal($value) . ' ';
    $nonPersonTerms = [
        'address','available','bluetooth','bottle','card','category','client',
        'description','document','electronics','email','fake','holder','information',
        'item','kitchen','mouse','notebook','office','payment','phone','sports',
        'status','stock','synthetic','test','this','water','wireless','yoga',
        'adreca','adreça','categoria','correu','descripcio','descripció','document',
        'disponible','estat','telefon','telèfon',
    ];

    foreach ($nonPersonTerms as $term) {
        if (str_contains($text, ' ' . normVal($term) . ' ')) return true;
    }

    return false;
}

/**
 * Aplica todos los patrones sobre un texto ya extraido.
 *
 * En modo normal, los patrones con always=false necesitan alguna palabra de
 * contexto en el documento. En modo --strict se aceptan aunque no haya contexto.
 * Devuelve una lista de hallazgos agrupados por tipo y sin duplicados.
 */
function scanText(string $text, bool $strict): array {
    $out = [];
    foreach (getPatterns() as $type => $cfg) {
        if (!preg_match_all($cfg['regex'], $text, $raw, PREG_SET_ORDER)) continue;

        // Context check per a patrons no-always
        if (!$cfg['always'] && !$strict) {
            $found = false;
            foreach ($cfg['ctx'] as $c) {
                if (mb_stripos($text, $c) !== false) { $found = true; break; }
            }
            if (!$found) continue;
        }

        // Deduplicar per valor normalitzat (insensible a majúscules)
        $unique = [];
        foreach ($raw as $m) {
            $orig = trim($m[1] ?? $m[0]);
            if ($type === 'Nom i cognoms' && isLikelyNameFalsePositive($orig)) continue;
            $norm = normVal($orig);
            if ($norm !== '' && !isset($unique[$norm])) $unique[$norm] = $orig;
        }
        if (empty($unique)) continue;

        $out[] = ['type' => $type, 'matches' => $unique, 'count' => count($unique)];
    }
    return $out;
}

// ════════════════════════════════════════════════════════════════
//  SCAN D'UN FITXER
// ════════════════════════════════════════════════════════════════

/**
 * Heuristica rapida para detectar binarios desconocidos.
 */
function isBin(string $path): bool {
    $fh = @fopen($path, 'rb');
    if (!$fh) return false;
    $c = fread($fh, 512);
    fclose($fh);
    return substr_count($c, "\0") > 2;
}

/**
 * Formatea bytes a una unidad legible para humanos.
 */
function fmtSize(int $b): string {
    if ($b < 1024)      return "{$b} B";
    if ($b < 1_048_576) return round($b / 1024, 1) . ' KB';
    return round($b / 1_048_576, 1) . ' MB';
}

/**
 * Escanea un unico fichero de principio a fin.
 *
 * Devuelve siempre la misma estructura:
 * - status: ok, sensitive, skipped o error.
 * - findings: hallazgos agrupados por tipo.
 * - total: numero total de coincidencias unicas.
 */
function scanFile(string $path, bool $strict): array {
    $ext  = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $base = ['file' => $path, 'filename' => basename($path),
             'size' => (int)@filesize($path), 'ext' => $ext,
             'status' => 'ok', 'message' => '', 'findings' => [], 'total' => 0];

    if (in_array($ext, SKIP_EXT))
        return $base + ['status' => 'skipped', 'message' => 'Format ignorat (' . strtoupper($ext) . ')'];

    if (!is_readable($path))
        return $base + ['status' => 'error', 'message' => 'Sense permisos de lectura'];

    if (!in_array($ext, SUPPORTED_EXT) && isBin($path))
        return $base + ['status' => 'skipped', 'message' => 'Fitxer binari desconegut'];

    $text = extractText($path);
    if (trim($text) === '')
        return $base + ['status' => 'error', 'message' => 'No s\'ha pogut extreure text'];

    $findings = scanText($text, $strict);
    $total    = array_sum(array_column($findings, 'count'));

    // Excepció: si l'única troballa és exactament UN nom complet i res més,
    // no considerem el fitxer com a sensible (evita falsos positius com
    // capçaleres de plantilles, signatures, autors, etc.).
    if (count($findings) === 1
        && $findings[0]['type'] === 'Nom i cognoms'
        && $findings[0]['count'] === 1) {
        $findings = [];
        $total    = 0;
    }

    return array_merge($base, [
        'findings' => $findings,
        'total'    => $total,
        'status'   => $total > 0 ? 'sensitive' : 'ok',
    ]);
}

/**
 * Recoge ficheros de un directorio, opcionalmente de forma recursiva.
 */
function collectFiles(string $dir, bool $rec): array {
    $iter = $rec
        ? new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS))
        : new DirectoryIterator($dir);
    $files = [];
    foreach ($iter as $f) if ($f->isFile()) $files[] = $f->getPathname();
    sort($files);
    return $files;
}

// ════════════════════════════════════════════════════════════════
//  INFORMES TXT i PDF
// ════════════════════════════════════════════════════════════════

/**
 * Construye el informe TXT final a partir de los resultados de escaneo.
 */
function generateTxt(array $results, string $scanPath, float $elapsed): string {
    $total     = count($results);
    $sensitive = count(array_filter($results, fn($r) => $r['status'] === 'sensitive'));
    $ok        = count(array_filter($results, fn($r) => $r['status'] === 'ok'));
    $skipped   = count(array_filter($results, fn($r) => $r['status'] === 'skipped'));
    $errors    = count(array_filter($results, fn($r) => $r['status'] === 'error'));
    $ts        = date('Y-m-d H:i:s');

    $lines = [];
    $lines[] = str_repeat('=', 60);
    $lines[] = "  INSPECTOR DE DADES SENSIBLES — v" . APP_VERSION;
    $lines[] = "  Generat: $ts";
    $lines[] = "  Ruta:    $scanPath";
    $lines[] = str_repeat('=', 60);
    $lines[] = "";
    $lines[] = "RESUM";
    $lines[] = str_repeat('-', 30);
    $lines[] = "  Total:     $total";
    $lines[] = "  Sensibles: $sensitive";
    $lines[] = "  Nets:      $ok";
    $lines[] = "  Omesos:    $skipped";
    $lines[] = "  Errors:    $errors";
    $lines[] = "  Temps:     {$elapsed}s";
    $lines[] = "";
    $lines[] = "RESULTATS";
    $lines[] = str_repeat('-', 60);

    foreach ($results as $r) {
        $status = match($r['status']) {
            'sensitive' => '[SENSIBLE]',
            'ok'        => '[NET]     ',
            'skipped'   => '[OMES]    ',
            default     => '[ERROR]   ',
        };
        $lines[] = "$status  " . $r['filename'];
        if ($r['status'] === 'sensitive' && !empty($r['findings'])) {
            foreach ($r['findings'] as $f) {
                $lines[] = "           → {$f['type']} ({$f['count']} coincidències)";
                // Al log no censurem: mostrem el valor original tal com s'ha trobat
                foreach (array_slice($f['matches'] ?? [], 0, 10) as $m) {
                    $lines[] = "             · " . $m;
                }
            }
        }
        if (!empty($r['message']) && $r['status'] !== 'ok') {
            $lines[] = "           " . $r['message'];
        }
    }

    $lines[] = "";
    $lines[] = str_repeat('=', 60);
    return implode("
", $lines) . "
";
}

/**
 * Genera un PDF minimo sin librerias externas.
 * El contenido real del informe se genera primero como texto y luego se coloca
 * en paginas PDF con fuente Courier.
 */
function generatePdf(array $results, string $scanPath, float $elapsed, string $outPath): void {
    // PDF mínim manual (text pla dins un PDF vàlid sense extensions externes)
    $txt  = generateTxt($results, $scanPath, $elapsed);
    $lines = explode("
", $txt);

    $pageW = 595; $pageH = 842;
    $margin = 40; $lineH = 13; $fontSize = 9;
    $maxLines = (int)(($pageH - $margin * 2) / $lineH);

    // Divideix en pàgines
    $pages = array_chunk($lines, $maxLines);

    $streamObjs = []; // [obj_num => stream_content]
    $pageObjs   = []; // obj nums dels pàgines
    $objNum = 3; // 1=catalog,2=pages, després continguts

    $body = '';
    $offsets = [];

    // Construïm streams de contingut
    foreach ($pages as $pageLines) {
        $yStart = $pageH - $margin;
        $stream  = "BT\n";
        $stream .= "/F1 {$fontSize} Tf\n";
        $stream .= "{$margin} {$yStart} Td\n";
        $stream .= "{$lineH} TL\n";
        foreach ($pageLines as $line) {
            $safe = str_replace(["\\", "(", ")"], ["\\\\", "\\(", "\\)"], $line);
            $stream .= "({$safe}) '\n";
        }
        $stream .= "ET\n";
        $streamObjs[$objNum] = $stream;
        $objNum++;
    }

    // Nums dels page content objs
    $contentStart = 3;
    $contentEnd   = $objNum - 1;

    // Page objs
    $pageStart = $objNum;
    foreach ($pages as $i => $_) {
        $pageObjs[] = $objNum;
        $objNum++;
    }

    $pagesObj = $objNum; // el /Pages obj
    $objNum++;
    $catalogObj = $objNum;

    // Ara escrivim el PDF
    $out = "%PDF-1.4
";

    // Content streams
    for ($n = $contentStart; $n <= $contentEnd; $n++) {
        $offsets[$n] = strlen($out);
        $s = $streamObjs[$n];
        $out .= "$n 0 obj
<< /Length " . strlen($s) . " >>
stream
$s
endstream
endobj
";
    }

    // Page objs
    foreach ($pageObjs as $i => $pn) {
        $cn = $contentStart + $i;
        $offsets[$pn] = strlen($out);
        $out .= "$pn 0 obj
<< /Type /Page /Parent $pagesObj 0 R /MediaBox [0 0 $pageW $pageH] /Contents $cn 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Courier >> >> >> >>
endobj
";
    }

    // Pages
    $kids = implode(' ', array_map(fn($n) => "$n 0 R", $pageObjs));
    $offsets[$pagesObj] = strlen($out);
    $out .= "$pagesObj 0 obj
<< /Type /Pages /Kids [$kids] /Count " . count($pageObjs) . " >>
endobj
";

    // Catalog
    $offsets[$catalogObj] = strlen($out);
    $out .= "$catalogObj 0 obj
<< /Type /Catalog /Pages $pagesObj 0 R >>
endobj
";

    // xref
    $xrefOffset = strlen($out);
    $allNums = array_merge(range($contentStart, $contentEnd), $pageObjs, [$pagesObj, $catalogObj]);
    $totalObjs = max($allNums) + 1;
    $out .= "xref
0 $totalObjs
";
    $out .= "0000000000 65535 f 
";
    for ($i = 1; $i < $totalObjs; $i++) {
        $off = $offsets[$i] ?? 0;
        $out .= str_pad((string)$off, 10, '0', STR_PAD_LEFT) . " 00000 n 
";
    }
    $out .= "trailer
<< /Size $totalObjs /Root $catalogObj 0 R >>
startxref
$xrefOffset
%%EOF
";

    file_put_contents($outPath, $out);
}

// ════════════════════════════════════════════════════════════════
//  INTERFÍCIE CLI
// ════════════════════════════════════════════════════════════════

/**
 * Aplica color ANSI solo si la salida es una terminal compatible.
 */
function cc(string $text, string $color): string {
    if (!function_exists('posix_isatty') || !posix_isatty(STDOUT)) return $text;
    $c = ['red'=>"\033[31m",'green'=>"\033[32m",'yellow'=>"\033[33m",
          'cyan'=>"\033[36m",'bold'=>"\033[1m",'dim'=>"\033[2m",'reset'=>"\033[0m"];
    return ($c[$color] ?? '') . $text . $c['reset'];
}

/**
 * Muestra la cabecera de ayuda en la CLI.
 */
function banner(): void {
    echo "\n";
    echo cc("  ┌────────────────────────────────────────────────────┐\n",'cyan');
    echo cc("  │",'cyan') . cc("  🔍 INSPECTOR DE DADES SENSIBLES  v".APP_VERSION."         ",'bold') . cc("│\n",'cyan');
    echo cc("  │",'cyan') . cc("     PHP pur · PDF · DOCX · XLSX · ODS · ODT · RTF   ",'dim') . cc("│\n",'cyan');
    echo cc("  └────────────────────────────────────────────────────┘\n",'cyan');
    echo "\n";
}

/**
 * Muestra uso, opciones soportadas y codigos de salida.
 */
function usage(): void {
    banner();
    echo cc("  ÚS:\n",'bold');
    echo "    php inspector.php <fitxer1> [fitxer2] ...\n";
    echo "    php inspector.php --dir <directori> [--recursive]\n\n";
    echo cc("  OPCIONS:\n",'bold');
    echo "    --dir <ruta>     Inspecciona tots els fitxers d'un directori\n";
    echo "    --recursive      Inclou subdirectoris (amb --dir)\n";
    echo "    --output <ruta>  Desa el report HTML a un fitxer concret\n";
    echo "    --json           Genera sortida JSON en comptes d'HTML\n";
    echo "    --strict         Inclou coincidències sense paraula de context\n";
    echo "    --help           Mostra aquesta ajuda\n\n";
    echo cc("  FORMATS SUPORTATS (100% PHP pur, sense cap dependència externa):\n",'bold');
    echo "    PDF  DOCX  XLSX  ODS  ODT  RTF\n";
    echo "    TXT  CSV  JSON  XML  LOG  MD  YAML  INI  SQL  ENV\n\n";
    echo cc("  FORMATS IGNORATS:\n",'bold');
    echo "    ZIP  RAR  7Z  TAR  GZ  i fitxers binaris\n\n";
    echo cc("  CODI DE SORTIDA:\n",'bold');
    echo "    0  →  Cap dada sensible detectada\n";
    echo "    1  →  S'han detectat dades sensibles (útil per a CI/CD)\n\n";
}

/**
 * Dibuja una barra de progreso simple mientras se escanean varios ficheros.
 */
function progress(int $cur, int $tot, string $file): void {
    $w  = 28;
    $p  = $tot > 0 ? $cur / $tot : 1;
    $fi = (int)($p * $w);
    $bar = str_repeat('█', $fi) . str_repeat('░', $w - $fi);
    $pct = str_pad((string)(int)($p * 100), 3) . '%';
    $fn  = mb_strlen($file) > 36 ? mb_substr($file, 0, 33) . '…' : str_pad($file, 36);
    printf("\r  [%s] %s  %s", cc($bar, 'cyan'), $pct, $fn);
}

/**
 * Imprime un resumen corto por consola despues del escaneo.
 */
function cliResults(array $results): void {
    echo "\n\n";
    $max = max(array_map(fn($r) => mb_strlen($r['filename']), $results) ?: [20]);
    $max = min($max + 2, 60);
    foreach ($results as $r) {
        $f = str_pad($r['filename'], $max);
        echo match($r['status']) {
            'sensitive' => "  ".cc($f,'bold').cc("  ⚠  SENSIBLE",'red')
                           .cc("  → ".implode(', ', array_column($r['findings'],'type')),'dim')."\n",
            'ok'        => "  ".cc($f,'dim').cc("  ✓  NET",'green')."\n",
            'skipped'   => "  ".cc($f,'dim').cc("  —  OMÈS",'yellow').cc("  ".$r['message'],'dim')."\n",
            default     => "  ".cc($f,'dim').cc("  ✗  ERROR",'dim').cc("  ".$r['message'],'dim')."\n",
        };
    }
}

// ════════════════════════════════════════════════════════════════
//  PUNT D'ENTRADA
// ════════════════════════════════════════════════════════════════

/**
 * Punto de entrada:
 * - parsea argumentos,
 * - decide ficheros a escanear,
 * - ejecuta scanFile(),
 * - escribe el informe,
 * - devuelve 0 si todo esta limpio o 1 si hay datos sensibles.
 */
function main(array $argv): int {
    $GLOBALS['_t0'] = microtime(true);
    $files  = [];
    $dir    = null;
    $rec    = false;
    $out    = null;
    $fmt    = 'txt'; // 'txt' o 'pdf'
    $strict = false;
    $args   = array_slice($argv, 1);

    for ($i = 0; $i < count($args); $i++) {
        switch ($args[$i]) {
            case '--help': case '-h':      usage(); return 0;
            case '--recursive': case '-r': $rec    = true; break;
            case '--pdf':                  $fmt    = 'pdf'; break;
            case '--txt':                  $fmt    = 'txt'; break;
            case '--strict':               $strict = true; break;
            case '--dir':                  $dir    = $args[++$i] ?? null; break;
            case '--output': case '-o':    $out    = $args[++$i] ?? null; break;
            default:
                if (is_file($args[$i]))       $files[] = $args[$i];
                elseif (is_dir($args[$i]))    { $dir = $args[$i]; }
                else fwrite(STDERR, cc("  Avís: no trobat: {$args[$i]}\n",'yellow'));
        }
    }

    if ($dir) {
        if (!is_dir($dir)) { fwrite(STDERR, cc("  ERROR: directori no trobat: $dir\n",'red')); return 2; }
        $files    = array_merge($files, collectFiles($dir, $rec));
        $scanPath = realpath($dir) ?: $dir;
    } elseif (!empty($files)) {
        $scanPath = count($files) === 1 ? (realpath($files[0]) ?: $files[0])
                                        : implode(', ', array_map('basename', $files));
    } else {
        usage(); return 0;
    }

    $results = [];
    foreach ($files as $f) {
        $results[] = scanFile($f, $strict);
    }

    $sensitive = count(array_filter($results, fn($r) => $r['status'] === 'sensitive'));

    echo $sensitive > 0 ? "No-Ok" : "Ok";
    echo "\n";

    // Genera log
    $elapsed = round(microtime(true) - ($GLOBALS['_t0'] ?? microtime(true)), 2);
    if (!$out) {
        if (!is_dir(LOG_DIR)) @mkdir(LOG_DIR, 0755, true);
        $out = LOG_DIR . '/report_' . date('Ymd_His') . '.' . $fmt;
    }
    if ($fmt === 'pdf') {
        generatePdf($results, $scanPath ?? '', $elapsed, $out);
    } else {
        file_put_contents($out, generateTxt($results, $scanPath ?? '', $elapsed));
    }

    return $sensitive > 0 ? 1 : 0;
}

exit(main($argv));
