#!/usr/bin/env python3
"""
analyse_logs.py — Analyse automatisée de logs SSH (auth.log) et Apache (access.log)

Détecte :
  - Brute force SSH : trop d'échecs "Failed password" depuis une même IP
                       dans une fenêtre de temps courte
  - Scan / énumération web : trop de requêtes (souvent 404) depuis une
                       même IP dans une fenêtre de temps courte
  - Tentatives d'injection : motifs suspects dans les chemins/requêtes
                       Apache (SQLi, XSS, path traversal, injection de commande)

Sortie :
  - events.csv   : chaque événement suspect détecté (SSH + Apache confondus)
  - summary.json : résumé statistique global
  - résumé lisible affiché dans le terminal

Usage :
  python3 analyse_logs.py --auth /var/log/auth.log --access /var/log/apache2/access.log --out-dir ./rapport
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Paramètres de détection (seuils ajustables selon le volume de ton labo)
# ---------------------------------------------------------------------------

SSH_FAIL_THRESHOLD = 10        # nombre d'échecs SSH déclenchant une alerte
SSH_WINDOW_SECONDS = 300       # ... observés sur cette fenêtre (5 min)
SSH_CAMPAIGN_GAP_SECONDS = 3600  # au-delà de cet écart entre deux échecs, on considère
                                  # qu'il s'agit d'une nouvelle campagne d'attaque distincte
                                  # (évite de mélanger plusieurs sessions séparées de plusieurs heures)

WEB_REQ_THRESHOLD = 50         # nombre de requêtes web déclenchant une alerte
WEB_WINDOW_SECONDS = 10        # ... observés sur cette fenêtre (10 sec)

# Motifs suspects recherchés dans le chemin/la requête Apache (après décodage URL,
# donc on matche directement sur des espaces et guillemets, pas sur %20/%27)
INJECTION_PATTERNS = {
    "Injection de commande": re.compile(r"(;|\||&&)\s*(cat|ls|wget|curl|nc|bash|sh)\b", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|etc/passwd|etc/shadow)", re.IGNORECASE),
    "XSS": re.compile(r"<script|javascript:", re.IGNORECASE),
    "Injection SQL": re.compile(r"'\s*(or|OR)\s*'?1'?\s*=\s*'?1|union\s+select|--\s|'--", re.IGNORECASE),
}

# ---------------------------------------------------------------------------
# Expressions régulières de parsing
# ---------------------------------------------------------------------------

# auth.log peut être au format syslog classique ("Nov 10 18:59:39 host ...")
# ou au format ISO 8601 ("2026-11-10T18:59:39.123456+01:00 host ...")
AUTH_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\S+T\S+)\s+\S+\s+sshd\[\d+\]:\s*(?P<msg>.*)$"
)
FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPTED_RE = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")

# access.log au format "Combined Log Format" standard d'Apache
ACCESS_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.*?) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)

CURRENT_YEAR = datetime.now().year


def parse_auth_timestamp(ts: str) -> datetime:
    """Convertit un timestamp auth.log (syslog ou ISO) en objet datetime."""
    ts = ts.strip()
    # Format ISO 8601 (rsyslog moderne)
    if "T" in ts:
        ts_clean = re.sub(r"\+\d{2}:\d{2}$|Z$", "", ts)
        ts_clean = ts_clean.split(".")[0]  # on retire les microsecondes
        return datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
    # Format syslog classique, sans année -> on utilise l'année courante
    return datetime.strptime(f"{CURRENT_YEAR} {ts}", "%Y %b %d %H:%M:%S")


def parse_access_timestamp(ts: str) -> datetime:
    """Convertit un timestamp access.log Apache en objet datetime."""
    # Exemple : 11/Nov/2026:16:31:23 +0100
    ts_no_tz = ts.split(" ")[0]
    return datetime.strptime(ts_no_tz, "%d/%b/%Y:%H:%M:%S")


# ---------------------------------------------------------------------------
# Parsing des fichiers
# ---------------------------------------------------------------------------

def parse_auth_log(path: Path):
    """Retourne la liste des événements SSH (échecs et réussites)."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = AUTH_LINE_RE.match(line)
            if not m:
                continue  # ignore les lignes qui ne sont pas des événements sshd (ex: sudo)
            msg = m.group("msg")

            fm = FAILED_RE.search(msg)
            if fm:
                try:
                    ts = parse_auth_timestamp(m.group("ts"))
                except ValueError:
                    continue
                events.append({
                    "timestamp": ts, "ip": fm.group("ip"), "user": fm.group("user"),
                    "result": "failed", "source": "ssh",
                })
                continue

            am = ACCEPTED_RE.search(msg)
            if am:
                try:
                    ts = parse_auth_timestamp(m.group("ts"))
                except ValueError:
                    continue
                events.append({
                    "timestamp": ts, "ip": am.group("ip"), "user": am.group("user"),
                    "result": "accepted", "source": "ssh",
                })
    return events


def parse_access_log(path: Path):
    """Retourne la liste des requêtes Apache parsées."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ACCESS_LINE_RE.match(line)
            if not m:
                continue
            try:
                ts = parse_access_timestamp(m.group("ts"))
            except ValueError:
                continue
            events.append({
                "timestamp": ts, "ip": m.group("ip"), "method": m.group("method"),
                "path": m.group("path"), "status": m.group("status"), "source": "web",
            })
    return events


# ---------------------------------------------------------------------------
# Détection
# ---------------------------------------------------------------------------

def split_into_campaigns(timestamps, gap_seconds):
    """
    Découpe une liste triée de timestamps en groupes ("campagnes") distincts :
    dès qu'un écart entre deux événements consécutifs dépasse gap_seconds,
    on démarre un nouveau groupe. Évite de mélanger des sessions d'attaque
    séparées de plusieurs heures/jours dans une même mesure.
    """
    if not timestamps:
        return []
    campaigns = [[timestamps[0]]]
    for ts in timestamps[1:]:
        if (ts - campaigns[-1][-1]).total_seconds() > gap_seconds:
            campaigns.append([ts])
        else:
            campaigns[-1].append(ts)
    return campaigns


def detect_ssh_bruteforce(ssh_events):
    """
    Regroupe les échecs par IP, les découpe en campagnes distinctes (voir
    split_into_campaigns), puis déclenche une alerte par campagne dès que
    SSH_FAIL_THRESHOLD échecs apparaissent dans une fenêtre glissante de
    SSH_WINDOW_SECONDS. Le délai jusqu'au succès est calculé UNIQUEMENT à
    l'intérieur de cette campagne, pas sur tout l'historique de l'IP.
    """
    by_ip = defaultdict(list)
    accepted_by_ip = defaultdict(list)
    for e in ssh_events:
        if e["result"] == "failed":
            by_ip[e["ip"]].append(e["timestamp"])
        else:
            accepted_by_ip[e["ip"]].append(e["timestamp"])

    alerts = []
    for ip, timestamps in by_ip.items():
        timestamps.sort()
        accepted_sorted = sorted(accepted_by_ip.get(ip, []))
        campaigns = split_into_campaigns(timestamps, SSH_CAMPAIGN_GAP_SECONDS)

        for campaign in campaigns:
            window = []
            triggered = False
            for ts in campaign:
                window.append(ts)
                window = [t for t in window if (ts - t).total_seconds() <= SSH_WINDOW_SECONDS]
                if len(window) >= SSH_FAIL_THRESHOLD:
                    triggered = True
            if not triggered:
                continue

            first_fail, last_fail = campaign[0], campaign[-1]
            # un succès "appartient" à cette campagne s'il tombe entre le premier
            # échec et peu après le dernier échec de cette même campagne
            success_ts = min(
                (
                    t for t in accepted_sorted
                    if first_fail <= t <= last_fail + timedelta(seconds=SSH_CAMPAIGN_GAP_SECONDS)
                ),
                default=None,
            )
            alerts.append({
                "type": "Brute force SSH",
                "ip": ip,
                "total_echecs": len(campaign),
                "premier_echec": first_fail.isoformat(),
                "dernier_echec": last_fail.isoformat(),
                "connexion_reussie": success_ts.isoformat() if success_ts else None,
                "delai_jusqu_succes_sec": (
                    (success_ts - first_fail).total_seconds() if success_ts else None
                ),
            })
    return alerts


def detect_web_scan(web_events):
    """Détecte un volume anormal de requêtes depuis une même IP sur une courte fenêtre."""
    by_ip = defaultdict(list)
    for e in web_events:
        by_ip[e["ip"]].append(e)

    alerts = []
    for ip, reqs in by_ip.items():
        reqs.sort(key=lambda e: e["timestamp"])
        timestamps = [e["timestamp"] for e in reqs]
        window = []
        triggered = False
        for ts in timestamps:
            window.append(ts)
            window = [t for t in window if (ts - t).total_seconds() <= WEB_WINDOW_SECONDS]
            if len(window) >= WEB_REQ_THRESHOLD and not triggered:
                triggered = True
                nb_404 = sum(1 for e in reqs if e["status"] == "404")
                alerts.append({
                    "type": "Scan / énumération web",
                    "ip": ip,
                    "total_requetes": len(reqs),
                    "requetes_404": nb_404,
                    "debut": timestamps[0].isoformat(),
                    "fin": timestamps[-1].isoformat(),
                })
    return alerts


def detect_injections(web_events):
    """Repère les requêtes Apache contenant un ou plusieurs motifs d'injection connus."""
    alerts = []
    for e in web_events:
        decoded_path = unquote(e["path"])  # %20 -> espace, %27 -> ', etc.
        matched_labels = [
            label for label, pattern in INJECTION_PATTERNS.items()
            if pattern.search(decoded_path)
        ]
        if matched_labels:
            alerts.append({
                "type": f"Tentative d'injection ({', '.join(matched_labels)})",
                "ip": e["ip"],
                "horodatage": e["timestamp"].isoformat(),
                "methode": e["method"],
                "chemin": e["path"],
                "statut_http": e["status"],
            })
    return alerts


# ---------------------------------------------------------------------------
# Rapport
# ---------------------------------------------------------------------------

def write_csv_report(alerts, out_path: Path):
    fieldnames = sorted({k for a in alerts for k in a.keys()})
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for a in alerts:
            writer.writerow(a)


def write_json_summary(summary: dict, out_path: Path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)


def print_console_summary(ssh_events, web_events, bf_alerts, scan_alerts, inj_alerts):
    print("=" * 60)
    print("RÉSUMÉ DE L'ANALYSE")
    print("=" * 60)
    print(f"Lignes SSH traitées   : {len(ssh_events)}")
    print(f"Lignes Apache traitées: {len(web_events)}")
    print("-" * 60)
    print(f"Alertes brute force SSH détectées : {len(bf_alerts)}")
    for a in bf_alerts:
        print(f"  - IP {a['ip']} : {a['total_echecs']} échecs"
              f"{' puis succès en ' + str(a['delai_jusqu_succes_sec']) + 's' if a['connexion_reussie'] else ''}")
    print(f"Alertes scan web détectées        : {len(scan_alerts)}")
    for a in scan_alerts:
        print(f"  - IP {a['ip']} : {a['total_requetes']} requêtes ({a['requetes_404']} en 404)")
    print(f"Tentatives d'injection détectées  : {len(inj_alerts)}")
    for a in inj_alerts:
        print(f"  - [{a['type']}] {a['ip']} -> {a['chemin'][:80]}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analyse automatisée de logs SSH et Apache.")
    parser.add_argument("--auth", default="/var/log/auth.log", help="Chemin vers auth.log")
    parser.add_argument("--access", default="/var/log/apache2/access.log", help="Chemin vers access.log")
    parser.add_argument("--out-dir", default="./rapport", help="Dossier de sortie pour les rapports")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ssh_events, web_events = [], []

    auth_path = Path(args.auth)
    if auth_path.exists():
        ssh_events = parse_auth_log(auth_path)
    else:
        print(f"[!] Fichier introuvable, ignoré : {auth_path}")

    access_path = Path(args.access)
    if access_path.exists():
        web_events = parse_access_log(access_path)
    else:
        print(f"[!] Fichier introuvable, ignoré : {access_path}")

    bf_alerts = detect_ssh_bruteforce(ssh_events) if ssh_events else []
    scan_alerts = detect_web_scan(web_events) if web_events else []
    inj_alerts = detect_injections(web_events) if web_events else []

    all_alerts = bf_alerts + scan_alerts + inj_alerts
    write_csv_report(all_alerts, out_dir / "events.csv")

    summary = {
        "genere_le": datetime.now().isoformat(),
        "lignes_ssh_analysees": len(ssh_events),
        "lignes_apache_analysees": len(web_events),
        "nb_alertes_bruteforce_ssh": len(bf_alerts),
        "nb_alertes_scan_web": len(scan_alerts),
        "nb_alertes_injection": len(inj_alerts),
        "seuils": {
            "ssh_fail_threshold": SSH_FAIL_THRESHOLD,
            "ssh_window_seconds": SSH_WINDOW_SECONDS,
            "web_req_threshold": WEB_REQ_THRESHOLD,
            "web_window_seconds": WEB_WINDOW_SECONDS,
        },
    }
    write_json_summary(summary, out_dir / "summary.json")

    print_console_summary(ssh_events, web_events, bf_alerts, scan_alerts, inj_alerts)
    print(f"\nRapports écrits dans : {out_dir.resolve()}")
    print(f"  - {out_dir / 'events.csv'}")
    print(f"  - {out_dir / 'summary.json'}")


if __name__ == "__main__":
    main()
