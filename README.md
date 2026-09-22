# Log Sentinnel

Agent Rust de surveillance de fichiers de logs en temps réel. `log_sentinnel` détecte les motifs configurés dans les nouvelles lignes ajoutées à un fichier, puis transmet chaque alerte à une API HTTP distante.

Le projet est conçu pour un usage d'agent local : il collecte également le nom d'hôte et l'adresse IP locale afin de contextualiser les alertes reçues par le serveur central.

## Fonctionnalités

- Surveillance en temps réel d'un fichier avec `notify`.
- Détection par liste de motifs configurables dans `rules.json`.
- Gestion de la rotation du fichier de log lorsque sa taille diminue.
- Rechargement à chaud des règles sans redémarrer l'agent.
- Envoi asynchrone des alertes au format JSON.
- Authentification des requêtes avec l'en-tête `X-Agent-Token`.
- Cinq tentatives d'envoi avec temporisation progressive en cas d'erreur réseau.
- Mode verbeux pour afficher les menaces détectées.

## Prérequis

- Rust stable et Cargo : <https://www.rust-lang.org/tools/install>
- Une API capable de recevoir les alertes `POST`.
- Un fichier de logs existant et accessible en lecture.

## Installation

Depuis la racine du projet :

```bash
cargo build --release
```

Le binaire est généré dans `target/release/log_sentinnel` (`log_sentinnel.exe` sous Windows).

Pour vérifier le projet avant compilation :

```bash
cargo check
```

## Configuration

### Arguments et variables d'environnement

Les arguments peuvent être fournis directement en ligne de commande ou, lorsque indiqué, par variable d'environnement.

| Argument | Variable | Obligatoire | Description |
| --- | --- | --- | --- |
| `-f`, `--file` | `LOG_FILE_PATH` | Oui | Chemin du fichier de logs à surveiller. |
| `-a`, `--api-url` | `API_URL` | Oui | URL de l'endpoint HTTP qui reçoit les alertes. |
| `-t`, `--token` | `AGENT_TOKEN` | Oui | Jeton transmis dans `X-Agent-Token`. |
| `-v`, `--verbose` | Aucune | Non | Affiche les événements de démarrage et les menaces détectées. |

Le chemin `rules.json` est actuellement recherché dans le répertoire de travail depuis lequel l'agent est lancé.

### Règles de détection

Chaque règle doit contenir les champs `title`, `pattern` et `level`. Les niveaux acceptés sont `Low`, `Meduim`, `High` et `Critical`.

Exemple de `rules.json` valide :

```json
[
  {
    "title": "Injection SQL",
    "pattern": "UNION SELECT",
    "level": "Critical"
  },
  {
    "title": "Tentative Path Traversal",
    "pattern": "../",
    "level": "High"
  },
  {
    "title": "Page introuvable",
    "pattern": " 404 ",
    "level": "Low"
  }
]
```

La comparaison est littérale et sensible à la casse : une alerte est déclenchée lorsque la nouvelle ligne contient `pattern`.

## Utilisation

### Arguments explicites

```bash
log_sentinnel.exe --file serveur.log --api-url https://soc.example.com/api/alerts --token "$env:AGENT_TOKEN" --verbose
```

Sous Linux/macOS :

```bash
./target/release/log_sentinnel \
  --file /var/log/nginx/access.log \
  --api-url https://soc.example.com/api/alerts \
  --token "$AGENT_TOKEN" \
  --verbose
```

### Variables d'environnement

Sous PowerShell :

```powershell
$env:LOG_FILE_PATH = "C:\logs\serveur.log"
$env:API_URL = "https://soc.example.com/api/alerts"
$env:AGENT_TOKEN = "votre-jeton"
.\target\release\log_sentinnel.exe --verbose
```

Sous Linux/macOS :

```bash
export LOG_FILE_PATH=/var/log/nginx/access.log
export API_URL=https://soc.example.com/api/alerts
export AGENT_TOKEN=votre-jeton
./target/release/log_sentinnel --verbose
```

L'agent reste actif jusqu'à l'arrêt du processus et traite uniquement les lignes ajoutées après son démarrage. Une rotation de log est détectée lorsque la taille du fichier devient inférieure à la position précédemment lue.

## Format des alertes

Pour chaque correspondance, l'agent envoie une requête `POST` à `API_URL` avec l'en-tête suivant :

```http
X-Agent-Token: votre-jeton
Content-Type: application/json
```

Exemple de corps JSON :

```json
{
  "title": "Injection SQL",
  "priorite": "Critical",
  "log_line": "10.0.0.99 GET /index.php?id=1 UNION SELECT username FROM users",
  "local_ip": "192.168.1.20",
  "hostname": "serveur-web-01",
  "type_attaque": "UNION SELECT"
}
```

Les réponses HTTP hors famille `2xx` et les erreurs réseau sont réessayées jusqu'à cinq fois. Le délai entre les tentatives augmente progressivement.

## Architecture

```text
src/
├── main.rs                    Initialisation, arguments et chargement initial des règles
├── detector.rs                Surveillance du log, hot reload et envoi des alertes
├── lib.rs                     Déclaration et réexport des modules
└── models/
    ├── configuration.rs       Arguments CLI et variables d'environnement
    ├── reporting.rs           Payload JSON et transport HTTP
    └── schema.rs              Règles de détection et niveaux de priorité
```

## Limites connues

- Les règles sont des recherches de sous-chaînes, sans expression régulière ni normalisation.
- Une ligne peut déclencher une seule alerte, correspondant à la première règle rencontrée.
- Les règles sont rechargées depuis `rules.json` dans le répertoire courant.
- Le jeton est fourni en clair par argument ou variable d'environnement ; utilisez les mécanismes de secrets de votre système d'exploitation ou de votre ordonnanceur.
- Le serveur distant doit définir son propre contrat d'API et gérer les éventuels doublons liés aux réessais.

## Licence

Ce projet est distribué sous licence GNU General Public License v3.0. Voir [LICENSE](LICENSE).
