# kura-ctl

Console de l'éditeur pour les sauvegardes [Kura](https://github.com/E-C-G/kura-agent) :
une application locale qui lit le compte Wasabi et montre, pour chaque bucket client,
l'espace utilisé, le coût estimé et l'écart avec le modèle de réglages recommandé.

**Lot 1 « Observer » : lecture seule.** La console ne modifie rien chez Wasabi ;
elle se contente d'une clé qui ne peut que lire.

## Ce que fait la console

- **Vue d'ensemble** : par client et par bucket, espace facturé, nombre d'objets,
  coût mensuel estimé (avec le minimum facturé de 1 To par compte), alertes
  (forte croissance sur 7 jours, statistiques non à jour depuis plus de 3 jours,
  écart critique au modèle).
- **Import des buckets** : la console liste les buckets du compte ; on rattache
  chacun à un code client (`acme`, proposé à partir du nom `acme-srv01`) et au poste
  sauvegardé.
- **Audit des réglages** : versioning, Object Lock (rétention par défaut),
  cycle de vie (anciennes versions, marqueurs de suppression orphelins, envois
  interrompus), stratégie du bucket. Chaque écart a une gravité et indique s'il
  se corrige maintenant ou seulement à la création du bucket (Object Lock).
- **Historique d'usage** : graphique quotidien par bucket, à partir de l'API Stats
  de Wasabi (jusqu'à 365 jours d'historique au premier import, puis complété chaque jour).
- **Journal d'audit** : chaque action (déverrouillage, import, relevé, réglages)
  est consignée dans la base, sans possibilité de modification ni de suppression.

Modèle de réglages appliqué par l'audit :

| Réglage | Attendu |
|---|---|
| Versioning | activé |
| Object Lock | activé, rétention par défaut GOVERNANCE 30 jours |
| Anciennes versions | supprimées après 90 jours |
| Marqueurs de suppression orphelins | supprimés |
| Envois multipart interrompus | abandonnés après 7 jours |
| Stratégie du bucket | refuse le HTTP non chiffré et la suppression de versions |

## Installation

Télécharger l'archive de son système depuis les
[releases](https://github.com/E-C-G/kura-ctl/releases), vérifier l'empreinte
avec `SHA256SUMS`, puis lancer `kura-ctl` (`kura-ctl.exe` sous Windows).
La console ouvre le navigateur sur `http://127.0.0.1:<port>`.

| Option | Effet |
|---|---|
| `--data <dossier>` | dossier de la base et du journal (défaut : dossier de configuration de l'utilisateur, `kura-ctl`) |
| `--port <n>` | port local fixe (défaut : un port libre) |
| `--no-browser` | ne pas ouvrir le navigateur (l'adresse est affichée) |
| `--reset` | effacer la clé d'administration du trousseau (mot de passe maître oublié) |
| `--version` | afficher la version |

Au premier lancement, la console demande :

1. un **mot de passe maître** (12 caractères au moins), redemandé à chaque démarrage ;
2. la **clé d'accès Wasabi de la console** (voir ci-dessous) ; elle est vérifiée
   auprès de Wasabi avant d'être enregistrée ;
3. le **tarif** au To et par mois, pour l'estimation des coûts (modifiable dans Réglages).

## Clé Wasabi de la console (lecture seule)

Créer dans la console Wasabi un sous-utilisateur dédié, par exemple `kura-ctl`,
avec un accès programmatique uniquement (pas d'accès à la console web), puis lui
attacher :

1. la stratégie gérée par Wasabi **`WasabiBucketStatsAccess`** (API Stats : espace utilisé par bucket) ;
2. la stratégie suivante, à créer dans *Policies* (stratégie IAM : pas de champ `Principal`) :

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListerLesBuckets",
      "Effect": "Allow",
      "Action": ["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
      "Resource": "*"
    },
    {
      "Sid": "LireLesReglages",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketVersioning",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketPolicy"
      ],
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

Aucune de ces actions ne donne accès au contenu des sauvegardes (pas de
`s3:GetObject`, pas de `s3:ListBucket`). Si une permission manque, la page du
bucket l'indique (« lecture refusée ») au lieu d'afficher un faux écart.

## Sécurité

- **Écoute locale uniquement** (`127.0.0.1`) et contrôle de l'en-tête `Host` : une page
  d'un autre site qui ferait pointer un nom de domaine vers la machine (DNS rebinding)
  est refusée.
- **Clé d'administration chiffrée** dans le trousseau du système (Gestionnaire
  d'identification Windows, Trousseau macOS, Secret Service sous Linux) : AES-256-GCM,
  clé dérivée du mot de passe maître par PBKDF2-SHA256 (600 000 itérations). La clé
  Wasabi n'est déchiffrée qu'en mémoire, tant que la console est déverrouillée.
- **Une seule session** : cookie `HttpOnly`, `SameSite=Strict` ; jeton anti-CSRF sur
  chaque formulaire ; contrôle de l'origine des requêtes ; politique de sécurité du
  contenu sans script en ligne ; page non intégrable dans un cadre.
- **Verrouillage** après 30 minutes d'inactivité (la clé est oubliée), ou par le bouton
  *Verrouiller*. Après 5 mots de passe faux, une minute d'attente.
- **Mot de passe maître oublié** : `kura-ctl --reset` efface la clé du trousseau ; il
  suffit de la ressaisir avec un nouveau mot de passe. Les données de la base
  (buckets, historique, journal) sont conservées.

La base (`kura-ctl.db`, SQLite) ne contient aucun secret : codes clients, réglages
relevés, historique d'usage, journal d'audit.

## Développement

Go 1.26. Dépendances : AWS SDK for Go v2 (client S3 seul), `modernc.org/sqlite`
(SQLite en Go pur, sans CGO), `github.com/zalando/go-keyring`.

```sh
go test ./...                 # pilote SQLite de production (modernc)
go test -tags mattn ./...     # variante avec github.com/mattn/go-sqlite3 (CGO)
go run ./cmd/kura-ctl --data ./tmp
```

Les binaires publiés sont compilés avec `CGO_ENABLED=0` pour Windows, macOS
(arm64, amd64) et Linux.

Arborescence :

| Paquet | Rôle |
|---|---|
| `cmd/kura-ctl` | point d'entrée, options, ouverture du navigateur |
| `internal/secrets` | coffre : mot de passe maître et clé d'administration dans le trousseau |
| `internal/store` | base SQLite : clients, buckets, usage quotidien, journal d'audit |
| `internal/wasabi` | lecture des réglages S3, API Stats, modèle de réglages et audit |
| `internal/jobs` | relevés (réglages, usage), actualisation quotidienne, synthèse et alertes |
| `internal/web` | serveur local, sessions, pages (htmx, Chart.js embarqués) |

## Licences tierces

Voir [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
