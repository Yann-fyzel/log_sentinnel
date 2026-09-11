# 🔍 log_sentinel

**log_sentinel** est un outil en ligne de commande (CLI) performant écrit en Rust, conçu pour les analystes SOC, les agents de sécurité et les équipes DevOps. Il permet de scanner rapidement des fichiers de logs textuels pour y détecter des signatures d'attaques informatiques courantes et exporter un rapport d'audit au format JSON.

---

## 🚀 Fonctionnalités

- 📊 **Scan Multi-Signatures Automatique** : Détection intégrée des injections SQL (`UNION SELECT`), des Directory Traversals (`../`) et des failles XSS (`<script>`).
- 🎯 **Recherche Personnalisée** : Possibilité de passer une signature spécifique en argument.
- ⚡ **Optimisation Mémoire** : Analyse rapide basée sur la gestion stricte des portées et des références.
- 💾 **Rapport Structuré** : Génération automatique d'un rapport d'audit `report.json` contenant le timestamp, la cible et le détail des lignes suspectes.
- 🛡️ **Zéro Crash** : Gestion robuste des erreurs système (fichiers introuvables, accès refusés) sans panique.

---

## 🛠️ Installation

Assurez-vous d'avoir installé l'environnement Rust sur votre machine.

```bash
# Clonez le monorepo (si ce n'est pas déjà fait)
git clone https://github.com
cd rust_mastery

# Compilez le projet en mode optimal (Release)
cargo build -p log_sentinel --release
```

Le binaire exécutable sera généré dans le dossier `target/release/log_sentinel`.

---

## 💻 Utilisation

### 1. Scan automatique par défaut

Analyse un fichier de log à la recherche de toutes les menaces connues :

```bash
log_sentinel --file serveur.log
```

### 2. Scan avec signature personnalisée et mode verbeux

```bash
log_sentinel --file serveur.log --query "ADMIN_LOGIN" --verbose
```

### 3. Spécifier un fichier de rapport personnalisé

```bash
log_sentinel -f serveur.log -o /var/log/audit_report.json
```

---

## 📋 Exemple de Rapport Généré (`report.json`)

```json
{
  "timestamp": "2026-09-11T14:55:00Z",
  "filepath_audited": "serveur.log",
  "total_alerts": 1,
  "lines_detected": [
    "10.0.0.99 - [11/Sep/2026] \"GET /index.php?id=1 UNION SELECT null, username FROM users\" 404"
  ]
}
```

---

## 🗂️ Architecture du Projet

L'outil applique les concepts avancés du livre officiel de Rust (Chapitres 7, 9, 10, 11, 12) :

- `src/main.rs` : Point d'entrée de l'application, parsing moderne via `clap`.
- `src/models.rs` : Modélisation des types de données, des schémas d'attaques et des structures d'exportation.
- `src/detector.rs` : Moteur d'analyse pure et logique de traitement des entrées/sorties.
