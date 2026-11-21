[200~# Log Analysis & Detection Lab

Simulation d'attaques (brute force SSH, scan web, injections) dans un laboratoire VMware, puis détection par un script Python et supervision dans Splunk.

> Projet pédagogique réalisé dans un environnement isolé, sur mes propres machines virtuelles.

## Architecture du labo

| Machine | Rôle | IP |
|---|---|---|
| Kali Linux | Attaquant | 192.168.154.129 |
| Ubuntu Desktop | Cible (openssh-server, apache2, Splunk Enterprise) | 192.168.154.130 |

Réseau VMware en mode NAT.

## Scénarios d'attaque

| Outil | Cible | Résultat |
|---|---|---|
| Hydra | SSH | Brute force avec une wordlist de 10 000 mots de passe (extrait de rockyou.txt), mot de passe trouvé après 9 233 tentatives, plus de 20 000 lignes d'échecs dans auth.log |
| Nikto | Apache | 702 requêtes enregistrées dans access.log |
| Gobuster | Apache | 4 613 chemins testés, 5 résultats (.htaccess, .hta, .htpasswd, index.html, server-status) |
| curl | Apache | 5 requêtes simulant SQLi, XSS, path traversal, injection de commande et contournement de login |

## Script de détection

`scripts/analyse_logs.py` (Python, approche par règles, sans machine learning) :
- parse `auth.log` et `access.log` ;
- détecte les campagnes de brute force SSH (fenêtre de temps + seuil), les scans web et les injections ;
- génère `rapport/events.csv` et `rapport/summary.json`.

## Supervision Splunk

- Index `analyse_de_logs` : 42 546 événements (SSH et Apache).
- Dashboard « Detection attaque » avec 6 panneaux : évolution des échecs SSH, top IP attaquantes SSH, total des échecs SSH, codes HTTP Apache, injections détectées, top IP de scan web.
- Alerte planifiée « Alerte Brute Force SSH » : plus de 10 échecs par IP, exécution toutes les heures.

## Structure du dépôt

- scripts/ : script Python de détection
- splunk/ : requêtes SPL et export du dashboard
- captures/ : captures d'écran du labo et du dashboard
- rapport/ : résultats générés (events.csv, summary.json)

## Enseignements

- Les commandes sudo polluent elles-mêmes les logs d'authentification.
- Une extinction brutale de la VM peut corrompre auth.log.
- MaxAuthTries et Fail2ban ne protègent pas de la même façon contre le brute force.
- Hydra parallélise ses tentatives, ce qui change la forme des logs.

## Auteur

Mehdi Forati, Master Ingénierie Informatique et Sécurité des Systèmes, Faculté des Sciences de Rabat.
