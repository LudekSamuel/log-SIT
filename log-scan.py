#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_scan.py

1) Stáhne hosts soubor "Unified hosts + fakenews" (StevenBlack/hosts) do cache.
   Cache se kontroluje podle HASHE (SHA-256 + ETag), ne podle stáří:
   - uložený otisk se porovná s otiskem souboru v cache (poškození/úprava),
   - server se zeptá, zda se obsah změnil (ETag); beze změny se nic nestahuje,
   - po stažení se porovná SHA-256 nového obsahu s uloženým.
2) Volitelně stáhne logy z git repozitáře do vlastní složky a udržuje je
   aktuální (výchozí obnova jednou za 7 dní).
3) Prohledá logy a vypíše TOP N adres ze seznamu StevenBlack, které se v lozích
   vyskytují, a TOP N log souborů. Vypisují se přesně záznamy z hosts souboru.
   Ve výpisu se standardně zobrazí jen konec adresy (stat.4u.pl -> 4u.pl); hledá se
   přitom podle přesných záznamů ze seznamu. Vypnutí: --no-sld-tld.
   Report se ukládá i do složky reports/. Změny jsou popsané v README.md.

Příklady:
    # logy z gitu (první spuštění = clone, další = pull, max. 1x za 7 dní)
    python3 hosts_log_scan.py --repo https://github.com/uzivatel/logy.git

    # jen podsložka repozitáře
    python3 hosts_log_scan.py --repo https://github.com/uzivatel/logy.git --subdir dns

    # logy už jsou lokálně
    python3 hosts_log_scan.py /cesta/k/logum
"""

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from functools import lru_cache, partial
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

HOSTS_URL = (
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/"
    "alternates/fakenews/hosts"
)
DEFAULT_CACHE_DIR = SCRIPT_DIR / ".cache" / "hosts_log_scan"
DEFAULT_LOGS_DIR = SCRIPT_DIR / "logs_repo"
DEFAULT_REPORT_DIR = SCRIPT_DIR / "reports"
CACHE_FILENAME = "hosts_unified_fakenews.txt"
META_FILENAME = "hosts_unified_fakenews.meta.json"
DEFAULT_SYNC_DAYS = 7

SINKHOLE_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "255.255.255.255"}
IGNORED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
}

# Jednoduchý (a rychlý) výraz pro slova. Text se před hledáním převede na malá
# písmena; okrajové znaky (koncová tečka v example.com.) se ořežou až u unikátních
# slov, ne u každého výskytu zvlášť.
TOKEN_RE = re.compile(r"[a-z0-9_.\-]+")

READ_CHUNK = 8 * 1024 * 1024        # kolik bajtů se čte najednou (hlídá paměť uvnitř úkolu)
POOL_MIN_BYTES = 20 * 1024 * 1024   # paralelně se jede až od této velikosti logů
PART_MB_DEFAULT = 32                # velikost úseku souboru (jeden úkol pro jeden proces)
MIN_PART_BYTES = 4 * 1024 * 1024    # menší úseky už by se nevyplatily (režie)

# Druhé úrovně veřejných přípon pod dvoupísmennými národními doménami
# (example.co.uk, example.com.au ...). Jednoduchá náhrada Public Suffix List.
SECOND_LEVEL_LABELS = {
    "co", "com", "org", "net", "gov", "edu", "ac", "ne", "or", "go", "mil", "nom", "gob",
}


# --------------------------------------------------------------------------
# Second-level + top-level doména
# --------------------------------------------------------------------------
@lru_cache(maxsize=500_000)
def registrable(host: str):
    """
    ads.tracker.example.com -> example.com
    www.bbc.co.uk           -> bbc.co.uk
    Vrací None pro IP adresy a slova bez tečky.
    """
    labels = host.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return None
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_LABELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# --------------------------------------------------------------------------
# Hosts soubor: stažení + cache kontrolovaná hashem
# --------------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_meta(meta_file: Path) -> dict:
    try:
        return json.loads(meta_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def get_hosts_file(cache_dir: Path, force_refresh: bool = False, offline: bool = False) -> Path:
    """
    Vrátí cestu k hosts souboru v cache a postará se, aby byl aktuální.

    Cache je platná, jen když SHA-256 souboru souhlasí s hashem v metadatech.
    Aktuálnost se ověřuje dotazem na server s ETagem (HTTP 304 = beze změny,
    nic se nestahuje). Po stažení se porovná SHA-256 nového obsahu s uloženým.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / CACHE_FILENAME
    meta_file = cache_dir / META_FILENAME
    meta = load_meta(meta_file)

    cache_ok = (
        cache_file.exists()
        and bool(meta.get("sha256"))
        and sha256_file(cache_file) == meta["sha256"]
    )
    if cache_file.exists() and not cache_ok:
        print("[cache] Hash cache nesedí s uloženým otiskem, stáhnu soubor znovu.")

    if offline:
        if cache_ok:
            print(f"[cache] Offline režim, používám cache (sha256 {meta['sha256'][:12]}…)")
            return cache_file
        sys.exit("[chyba] Offline režim, ale platná cache neexistuje.")

    def use_cache_or_exit(reason: str) -> Path:
        if cache_ok:
            print(f"[varování] {reason}, použiji cache.", file=sys.stderr)
            return cache_file
        sys.exit(f"[chyba] {reason} a platná cache neexistuje.")

    headers = {"User-Agent": "hosts-log-scan/1.0"}
    if cache_ok and meta.get("etag") and not force_refresh:
        headers["If-None-Match"] = meta["etag"]

    print(f"[download] Kontroluji {HOSTS_URL}")
    try:
        req = urllib.request.Request(HOSTS_URL, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
            etag = resp.headers.get("ETag")
        if not data.strip():
            raise ValueError("stažený soubor je prázdný")
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and cache_ok:
            print(f"[cache] Server hlásí beze změny, používám cache "
                  f"(sha256 {meta['sha256'][:12]}…)")
            return cache_file
        return use_cache_or_exit(f"Server vrátil chybu {exc.code}")
    except Exception as exc:  # noqa: BLE001
        return use_cache_or_exit(f"Stažení selhalo ({exc})")

    new_hash = sha256_bytes(data)
    if cache_ok and new_hash == meta["sha256"]:
        print(f"[cache] Hash se nezměnil (sha256 {new_hash[:12]}…), cache zůstává.")
        meta["etag"] = etag or meta.get("etag")
        meta["checked_at"] = datetime.now().isoformat(timespec="seconds")
        meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return cache_file

    tmp = cache_file.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(cache_file)
    meta = {
        "url": HOSTS_URL,
        "sha256": new_hash,
        "etag": etag,
        "size": len(data),
        "checked_at": datetime.now().isoformat(timespec="seconds"),
    }
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[download] Uloženo do cache: {cache_file} ({len(data) / 1024:.0f} kB, "
          f"sha256 {new_hash[:12]}…)")
    return cache_file


# --------------------------------------------------------------------------
# Logy z gitu: clone / pull
# --------------------------------------------------------------------------
def run_git(args, cwd=None) -> None:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} selhal:\n{result.stderr.strip()}")


def sync_logs_repo(repo_url: str, logs_dir: Path, sync_days: float, force: bool) -> Path:
    """
    Zajistí, že v logs_dir/repo je aktuální kopie repozitáře.
    - poprvé clone (shallow, jen poslední verze),
    - potom aktualizace nejvýše jednou za sync_days dní (nebo při --sync-now).
    Vrací cestu ke složce s repozitářem.
    """
    if shutil.which("git") is None:
        sys.exit("[chyba] Není nainstalovaný git. Stáhni ho z https://git-scm.com/")

    logs_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = logs_dir / "repo"
    marker = logs_dir / ".last_sync"

    if not (repo_dir / ".git").exists():
        print(f"[git] Klonuji {repo_url} -> {repo_dir}")
        try:
            run_git(["clone", "--depth", "1", repo_url, str(repo_dir)])
        except RuntimeError as exc:
            sys.exit(f"[chyba] {exc}")
        marker.write_text(str(time.time()))
        return repo_dir

    age_days = float("inf")
    if marker.exists():
        try:
            age_days = (time.time() - float(marker.read_text())) / 86400
        except ValueError:
            pass

    if force or age_days >= sync_days:
        age_txt = "nikdy" if age_days == float("inf") else f"před {age_days:.1f} dny"
        print(f"[git] Aktualizuji logy v {repo_dir} (poslední obnova: {age_txt})")
        try:
            run_git(["fetch", "--depth", "1", "origin"], cwd=repo_dir)
            run_git(["reset", "--hard", "@{u}"], cwd=repo_dir)
            marker.write_text(str(time.time()))
        except RuntimeError as exc:
            print(f"[varování] Aktualizace selhala, použiji stávající kopii.\n{exc}",
                  file=sys.stderr)
    else:
        print(f"[git] Logy jsou čerstvé ({age_days:.1f} d < {sync_days:g} d), neobnovuji.")
    return repo_dir


# --------------------------------------------------------------------------
# Parsování hosts souboru
# --------------------------------------------------------------------------
def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_hosts(path: Path):
    """Vrátí (množina domén, množina IP adres) z hosts souboru."""
    domains = set()
    ips = set()

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            target_ip, hostnames = parts[0], parts[1:]

            # Sinkhole IP (0.0.0.0, 127.0.0.1) se nehledá, dávala by samé falešné zásahy.
            if target_ip not in SINKHOLE_IPS and is_ip(target_ip):
                ips.add(target_ip)

            for host in hostnames:
                host = host.lower().rstrip(".")
                if host in IGNORED_HOSTNAMES:
                    continue
                # is_ip() je pomalé, volá se jen u slov, která IP adresa být může
                if (host[:1].isdigit() or ":" in host) and is_ip(host):
                    if host not in SINKHOLE_IPS:
                        ips.add(host)
                elif "." in host:
                    domains.add(host)
    return domains, ips


# --------------------------------------------------------------------------
# Procházení logů
# --------------------------------------------------------------------------
def iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".git" not in p.relative_to(root).parts:
            yield p


def open_log(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


# Seznamy z hosts souboru. Nastavují se jednou (v hlavním procesu i v každém
# pomocném procesu), aby se nemusely posílat s každým souborem znovu.
_MATCH: set = set()     # záznamy ze seznamu StevenBlack
_IPS: set = set()


def _init_worker(match_domains, ips):
    global _MATCH, _IPS
    _MATCH = match_domains
    _IPS = ips


def group_by_end(hits: Counter) -> Counter:
    """Zkrátí nalezené adresy na second-level + TLD: stat.4u.pl -> 4u.pl.
    IP adresy zůstanou beze změny."""
    grouped: Counter = Counter()
    for item, count in hits.items():
        grouped[registrable(item) or item] += count
    return grouped


def iter_blocks(path: Path, start: int, end: int):
    """
    Vrací bloky (bytes) s CELÝMI řádky, které ZAČÍNAJÍ v bajtovém úseku [start, end).

    Pravidla, aby se žádný řádek neztratil ani nepočítal dvakrát:
    - úsek, který nezačíná na začátku souboru, zahodí první (rozříznutý) řádek,
      patří úseku před ním;
    - řádek, který přesahuje hranici `end`, se dočte do konce, patří tomuto úseku.
    Zalomení řádku je v UTF-8 jediný bajt, který se nikdy nevyskytne uvnitř
    jiného znaku, takže řez nerozbije diakritiku.
    Soubory .gz se nedají dělit (číst se musí od začátku), jsou vždy jeden úsek.
    """
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as fh:
        if start > 0:
            fh.seek(start - 1)
            fh.readline()                 # dočte rozříznutý řádek (patří předchozímu úseku)
        pos = fh.tell()
        while pos < end:
            block = fh.read(min(READ_CHUNK, end - pos))
            if not block:
                break
            if not block.endswith(b"\n"):
                block += fh.readline()    # dočti rozečtený řádek, ať se slovo nerozseká
            pos = fh.tell()
            yield block


def scan_part(task, root_str: str, subdomains: bool):
    """
    Prohledá jeden úkol = úsek souboru (cesta, začátek, konec).
    Vrací (relativní cesta, Counter nálezů, chyba).

    Rychlost: text se čte po velkých blocích, rozseká na slova jedním voláním
    regulárního výrazu a spočítá se Counterem (vše v C). Python pak porovnává
    jen UNIKÁTNÍ slova, ne každý výskyt zvlášť.
    """
    path_str, start, end = task
    path = Path(path_str)
    rel = str(path.relative_to(root_str))
    hits: Counter = Counter()
    try:
        for block in iter_blocks(path, start, end):
            text = block.decode("utf-8", errors="replace").lower()
            words = Counter()
            for raw, count in Counter(TOKEN_RE.findall(text)).items():
                word = raw.strip(".-_")
                if word:
                    words[word] += count

            for ip in _IPS.intersection(words):          # IP adresy: vždy přesná shoda
                hits[ip] += words[ip]

            for dom in _MATCH.intersection(words):       # přesné shody se záznamy seznamu
                hits[dom] += words[dom]

            if subdomains:                                # shody přes nadřazený záznam
                for word, count in words.items():
                    if word in _MATCH or "." not in word:
                        continue
                    labels = word.split(".")
                    for i in range(1, len(labels) - 1):
                        parent = ".".join(labels[i:])
                        if parent in _MATCH:
                            hits[parent] += count
                            break
        return rel, hits, None
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        return rel, hits, f"{path}: {exc}"


def make_tasks(files, part_bytes: int):
    """
    Rozdělí soubory na úkoly (cesta, začátek, konec). Velký soubor se rozdělí na
    stejně velké úseky, malý a každý .gz zůstanou celé. Největší úkoly jdou první,
    aby na konci nezůstával jeden dlouhý úkol sám.
    """
    weighted = []
    for f in files:
        size = f.stat().st_size
        if f.suffix == ".gz":
            weighted.append((size * 5, (str(f), 0, sys.maxsize)))   # po rozbalení bývá větší
            continue
        parts = max(1, round(size / part_bytes))
        for i in range(parts):
            start, end = size * i // parts, size * (i + 1) // parts
            weighted.append((end - start, (str(f), start, end)))
    weighted.sort(key=lambda item: -item[0])
    return [task for _, task in weighted]


def scan_logs(root: Path, match_domains, ips, subdomains: bool, workers: int = 1,
              group_sld: bool = False, part_mb: float = PART_MB_DEFAULT):
    domain_hits = Counter()
    file_hits = Counter()
    file_unique = {}

    files = list(iter_files(root))
    total_bytes = sum(f.stat().st_size for f in files)
    _init_worker(match_domains, ips)

    use_pool = workers > 1 and total_bytes >= POOL_MIN_BYTES
    if use_pool:
        # Úseky nesmí být tak velké, aby se pracovníkům nedostalo práce; ani tak
        # malé, aby se víc času ztratilo režií.
        part_bytes = int(part_mb * 1024 * 1024)
        part_bytes = min(part_bytes, max(MIN_PART_BYTES, total_bytes // (workers * 4)))
    else:
        part_bytes = sys.maxsize          # bez paralelismu zůstává každý soubor celý
    tasks = make_tasks(files, part_bytes)

    worker = partial(scan_part, root_str=str(root), subdomains=subdomains)
    results = None
    if use_pool and len(tasks) > 1:
        n = min(workers, len(tasks))
        try:
            print(f"[scan] Paralelně: {n} procesů, {len(tasks)} úkolů "
                  f"(úseky souborů po ~{part_bytes / 1024 / 1024:.0f} MB)")
            with ProcessPoolExecutor(max_workers=n, initializer=_init_worker,
                                     initargs=(match_domains, ips)) as pool:
                # chunksize=1: volný proces si hned bere další úkol z fronty
                results = list(pool.map(worker, tasks, chunksize=1))
        except Exception as exc:  # noqa: BLE001
            print(f"[varování] Paralelně to nešlo ({exc}), jedu po jednom.", file=sys.stderr)
            results = None
    if results is None:
        results = [worker(t) for t in tasks]

    per_file: dict = {}
    errors = set()
    for rel, hits, error in results:
        if error:
            errors.add(error)
        per_file.setdefault(rel, Counter()).update(hits)   # sečtení výsledků částí souboru
    for error in sorted(errors):
        print(f"[varování] Nelze přečíst {error}", file=sys.stderr)

    for rel in sorted(per_file):
        hits = per_file[rel]
        if hits:
            if group_sld:
                hits = group_by_end(hits)   # seskupení až PO filtrování podle seznamu
            domain_hits.update(hits)
            file_hits[rel] = sum(hits.values())
            file_unique[rel] = set(hits)

    return domain_hits, file_hits, file_unique, len(files)


# --------------------------------------------------------------------------
# Výstup
# --------------------------------------------------------------------------
def format_duration(seconds: float) -> str:
    """Čitelný zápis doby trvání."""
    if seconds < 10:
        return f"{seconds:.2f} s"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, sec = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes} min {sec:02d} s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d} min {sec:02d} s"


def build_report(domain_hits, file_hits, file_unique, files_scanned, top_n, source,
                 scan_seconds: float, mode_label: str) -> str:
    out = []
    out.append("=" * 70)
    out.append(f"Report ze dne {datetime.now():%Y-%m-%d %H:%M}")
    out.append(f"Zdroj logů: {source}")
    out.append(f"Doba hledání: {format_duration(scan_seconds)}")
    out.append(f"Prohledáno souborů: {files_scanned}")
    out.append(f"Souborů se zásahem: {len(file_hits)}")
    out.append(f"Unikátních nalezených domén/IP: {len(domain_hits)}")
    out.append(f"Celkem zásahů: {sum(domain_hits.values())}")

    if not domain_hits:
        out.append("\nNic z hosts souboru nebylo v lozích nalezeno.")
        return "\n".join(out)
    out.append(f"#TOP {top_n} nalezených adres ze seznamu StevenBlack (počet výskytů)")
    for i, (item, count) in enumerate(domain_hits.most_common(top_n), 1):
        out.append(f"{i:>3}. {count:>8}x  {item};")
    out.append(f"#TOP {top_n} log souborů (počet zásahů / unikátních domén)")
    for i, (fname, count) in enumerate(file_hits.most_common(top_n), 1):
        out.append(f"{i:>3}. {count:>8}x  {len(file_unique[fname]):>4} unik.  {fname};")
    return "\n".join(out)


def main():
    run_start = time.perf_counter()

    # Aby výpis s češtinou nespadl na Windows konzoli s jiným kódováním.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass

    ap = argparse.ArgumentParser(
        description="Hledá domény/IP z hosts (Unified + fakenews) v logových souborech."
    )
    ap.add_argument("adr", type=Path, nargs="?",
                    help="adresář s logy (pokud nepoužiješ --repo)")
    ap.add_argument("--repo", metavar="URL",
                    help="URL git repozitáře s logy (stáhne se a udržuje se aktuální)")
    ap.add_argument("--subdir", default="",
                    help="prohledávat jen tuto podsložku repozitáře")
    ap.add_argument("--logs-dir", type=Path, default=DEFAULT_LOGS_DIR,
                    help=f"kam ukládat stažené logy (výchozí {DEFAULT_LOGS_DIR})")
    ap.add_argument("--sync-days", type=float, default=DEFAULT_SYNC_DAYS,
                    help=f"nejčastější obnova logů z gitu ve dnech (výchozí {DEFAULT_SYNC_DAYS})")
    ap.add_argument("--sync-now", action="store_true",
                    help="obnovit logy z gitu hned, bez ohledu na stáří")
    ap.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR,
                    help=f"kam ukládat reporty (výchozí {DEFAULT_REPORT_DIR})")
    ap.add_argument("--top", type=int, default=10,
                    help="počet řádků ve statistice (výchozí 10)")
    ap.add_argument("--sld-tld", action=argparse.BooleanOptionalAction, default=True,
                    help="ve výpisu ukázat jen konec adresy (stat.4u.pl -> 4u.pl). Hledá se "
                         "dál podle přesných záznamů ze seznamu StevenBlack, takže běžný "
                         "provoz (např. google.com) se nepočítá. Vypnutí: --no-sld-tld "
                         "(výchozí: %(default)s)")
    ap.add_argument("--subdomains", action="store_true",
                    help="sub.ads.example.com v logu se spáruje se záznamem ads.example.com "
                         "ze seznamu (výpis ukáže vždy záznam ze seznamu)")
    ap.add_argument("--refresh", action="store_true",
                    help="znovu stáhnout hosts soubor, ignorovat ETag")
    ap.add_argument("--offline", action="store_true",
                    help="nekontrolovat server, použít hosts soubor z cache")
    ap.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR,
                    help=f"adresář cache hosts souboru (výchozí {DEFAULT_CACHE_DIR})")
    ap.add_argument("--part-mb", type=float, default=PART_MB_DEFAULT,
                    help="největší velikost úseku souboru v MB; velké logy se dělí na úseky, "
                         f"které se zpracují paralelně (výchozí {PART_MB_DEFAULT})")
    ap.add_argument("--workers", type=int, default=min(os.cpu_count() or 1, 8),
                    help="počet procesů pro velké logy (výchozí podle počtu jader, max. 8)")
    args = ap.parse_args()

    if not args.repo and not args.adr:
        ap.error("zadej buď adresář s logy, nebo --repo URL")

    # 1) logy
    if args.repo:
        root = sync_logs_repo(args.repo, args.logs_dir, args.sync_days, args.sync_now)
        source = args.repo
    else:
        root = args.adr
        source = str(args.adr)
    if args.subdir:
        root = root / args.subdir
    if not root.is_dir():
        sys.exit(f"[chyba] {root} není adresář")

    # 2) hosts
    hosts_path = get_hosts_file(args.cache_dir, args.refresh, args.offline)
    domains, ips = parse_hosts(hosts_path)

    match_domains = domains
    mode_label = ("přesné adresy ze seznamu StevenBlack"
                  + (" (i subdomény záznamů)" if args.subdomains else ""))
    if args.sld_tld:
        mode_label += ", výpis zkrácen na second-level + TLD (stat.4u.pl -> 4u.pl)"
    print(f"[hosts] Načteno {len(domains)} domén a {len(ips)} IP adres")

    # 3) scan + report
    print(f"[scan] Prohledávám {root} ...")
    scan_start = time.perf_counter()
    result = scan_logs(root, match_domains, ips, args.subdomains, args.workers, args.sld_tld,
                       args.part_mb)
    scan_seconds = time.perf_counter() - scan_start

    report = build_report(*result, top_n=args.top, source=source,
                          scan_seconds=scan_seconds, mode_label=mode_label)
    print("\n" + report)

    args.report_dir.mkdir(parents=True, exist_ok=True)
    report_file = args.report_dir / f"report_{datetime.now():%Y-%m-%d}.txt"
    report_file.write_text(report + "\n", encoding="utf-8")
    print(f"\n[report] Uloženo do {report_file}")
    print(f"[čas] Hledání: {format_duration(scan_seconds)}, "
          f"celý běh včetně stažení: {format_duration(time.perf_counter() - run_start)}")


if __name__ == "__main__":
    main()