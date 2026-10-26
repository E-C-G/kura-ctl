# kura-ctl

Console de l'éditeur pour les sauvegardes [Kura](https://github.com/E-C-G/kura-agent) :
une application locale qui lit le compte Wasabi et montre, pour chaque bucket client,
l'espace utilisé, le coût estimé et l'écart avec le modèle de réglages recommandé,
puis corrige ces réglages et crée la clé limitée de chaque poste.

| Lot | Contenu | État |
| --- | --- | --- |
| 1 « Observer » | usage, coûts, audit des réglages, journal ; aucune écriture chez Wasabi | **fait** |
| 2 « Sécuriser l'existant » | clé `kura-ctl-admin`, stratégie de bucket, cycle de vie, rétention, clé de poste et paquet `.kura` | **fait** |
| 3 « Préparer les postes » | paquets d'installation complets, rotation guidée | à faire |
| 4 « Créer proprement » | bucket neuf depuis le modèle, avec Object Lock | à faire |

Toute écriture chez Wasabi passe par un aperçu de ce qui sera écrit, la saisie du nom du
bucket, puis une relecture du réglage chez Wasabi ; le résultat va au journal d'audit.

## Ce que fait la console

- **Vue d'ensemble** : par client et par bucket, espace facturé, nombre d'objets,
  coût mensuel estimé, alertes (forte croissance sur 7 jours, statistiques non à
  jour depuis plus de 3 jours, écart critique ou important au modèle, réglage illisible).
- **Import des buckets** : la console liste les buckets du compte ; on rattache
  chacun à un code client (`acme`, proposé à partir du nom `acme-srv01`) et au poste
  sauvegardé.
- **Audit des réglages** : versioning, Object Lock (rétention par défaut),
  cycle de vie (anciennes versions, marqueurs de suppression orphelins, envois
  interrompus), stratégie du bucket. Chaque écart a une gravité et indique s'il
  se corrige maintenant ou seulement à la création du bucket (Object Lock).
- **Historique d'usage** : graphique quotidien par bucket, à partir de l'API Stats
  de Wasabi : 365 jours d'historique à l'import, puis complété à chaque
  déverrouillage (et toutes les 24 h si la console reste ouverte et déverrouillée).
  Les jours où la console est restée fermée sont rattrapés.
- **Journal d'audit** : chaque action (déverrouillage, import, relevé, réglages)
  est consignée dans la base, sans possibilité de modification ni de suppression.

Coût estimé, selon la formule publiée par Wasabi : chaque jour,
`max(stockage actif du compte, 1 To) + stockage supprimé encore facturé`, le stockage
actif comptant les objets arrondis et les métadonnées, en To de 1024 Go de 1024³
octets ; l'estimation mensuelle est la moyenne des 30 derniers jours connus × le tarif.
La facture Wasabi fait foi.

Si un réglage ne peut pas être relu (panne passagère, droit retiré à la clé), l'écart
déjà connu reste affiché, évalué sur la dernière valeur lue, et le réglage illisible
devient lui-même une alerte.

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
La console ouvre le navigateur sur une adresse locale de la forme
`http://kura-<aléa>.localhost:<port>/` (voir *Sécurité*). Si le navigateur ne
résout pas ce nom, relancer avec `--plain-host` pour servir sur `http://127.0.0.1:<port>/`.

| Option | Effet |
|---|---|
| `--data <dossier>` | dossier de la base et du journal (défaut : dossier de configuration de l'utilisateur, `kura-ctl`) |
| `--port <n>` | port local fixe (défaut : un port libre) |
| `--no-browser` | ne pas ouvrir le navigateur (l'adresse est affichée) |
| `--plain-host` | servir sur `127.0.0.1` plutôt que sous un nom aléatoire en `.localhost` |
| `--reset` | effacer la clé d'administration du trousseau (mot de passe maître oublié) |
| `--version` | afficher la version |

Au premier lancement, la console demande :

1. un **mot de passe maître** (12 caractères au moins), redemandé à chaque démarrage ;
2. la **clé d'accès Wasabi de la console** (voir ci-dessous) ; elle est vérifiée
   auprès de Wasabi avant d'être enregistrée ;
3. le **tarif** au To et par mois, pour l'estimation des coûts (modifiable dans Réglages).

## Clé Wasabi de la console

Deux possibilités : une clé **en lecture seule** suffit au lot 1 (observer) ; les écritures
du lot 2 demandent l'utilisateur **`kura-ctl-admin`** (voir plus bas), dont la clé se saisit
dans *Réglages → Clé d'administration*. La console refuse la clé du compte racine.

### Lecture seule

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

### `kura-ctl-admin` (lot 2)

1. *Policies → Create Policy* : nom `kura-ctl-admin`, contenu ci-dessous (aussi affiché dans
   *Réglages*).
2. *Users → Create User* : `kura-ctl-admin`, accès programmatique seulement ; lui attacher
   cette stratégie et la stratégie gérée `WasabiBucketStatsAccess`.
3. Dans la console : *Réglages → Clé d'administration*, saisir sa clé. Supprimer ensuite la
   clé en lecture seule dans Wasabi.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SeConnaitre",
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ListUsers"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Sid": "GererLesUtilisateursDesPostes",
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser",
        "iam:GetUser",
        "iam:PutUserPolicy",
        "iam:GetUserPolicy",
        "iam:ListUserPolicies",
        "iam:CreateAccessKey",
        "iam:ListAccessKeys",
        "iam:UpdateAccessKey",
        "iam:DeleteAccessKey",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": [
        "arn:aws:iam::*:user/kura-*"
      ]
    },
    {
      "Sid": "JamaisSurLaConsoleElleMeme",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:UpdateUser",
        "iam:PutUserPolicy",
        "iam:DeleteUserPolicy",
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy",
        "iam:CreateAccessKey",
        "iam:UpdateAccessKey",
        "iam:DeleteAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AddUserToGroup"
      ],
      "Resource": [
        "arn:aws:iam::*:user/kura-ctl*"
      ]
    },
    {
      "Sid": "ReglerLesBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:CreateBucket",
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning",
        "s3:GetBucketObjectLockConfiguration",
        "s3:PutBucketObjectLockConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:PutLifecycleConfiguration",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
```

- Aucun accès au contenu des sauvegardes (ni `GetObject`, ni `DeleteObject…`), aucun
  contournement de rétention (`BypassGovernanceRetention`).
- Droits IAM limités aux utilisateurs `kura-*` (les postes) ; refus explicite sur `kura-ctl*` :
  la console ne peut ni modifier ses propres droits ni se créer de clé.
- `CreateBucket` sert au lot 4.

## Sécuriser un bucket existant (lot 2)

Sur la page d'un bucket, section *Sécuriser le bucket* :

| Réglage | Ce qui est écrit |
| --- | --- |
| Stratégie de bucket | refus du HTTP non chiffré ; refus, à tous sauf `kura-ctl-admin` et au compte racine, de supprimer une version, de contourner une rétention, de changer le cycle de vie, le versioning ou l'Object Lock. La stratégie elle-même reste modifiable : la console ne peut pas s'enfermer dehors. |
| Cycle de vie | anciennes versions supprimées après 90 jours, marqueurs orphelins nettoyés, envois interrompus abandonnés après 7 jours ; les versions courantes ne sont jamais expirées |
| Rétention par défaut | gouvernance 30 jours, si l'Object Lock est actif (il ne s'active qu'à la création du bucket) |

L'aperçu montre le réglage actuel et le nouveau : chaque écriture **remplace** le réglage
entier (une stratégie qui accordait autre chose est remplacée). Exemple de stratégie générée :

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "HTTPSObligatoire",
      "Effect": "Deny",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::acme-srv01",
        "arn:aws:s3:::acme-srv01/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "ReserveALaConsole",
      "Effect": "Deny",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "s3:DeleteObjectVersion",
        "s3:BypassGovernanceRetention",
        "s3:PutLifecycleConfiguration",
        "s3:PutBucketVersioning",
        "s3:PutBucketObjectLockConfiguration"
      ],
      "Resource": [
        "arn:aws:s3:::acme-srv01",
        "arn:aws:s3:::acme-srv01/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::100000000042:user/kura-ctl-admin",
            "arn:aws:iam::100000000042:root"
          ]
        }
      }
    }
  ]
}
```

## Clé d'un poste et paquet `.kura` (lot 2)

*Créer une clé et un paquet* crée si besoin l'utilisateur `kura-<client>-<poste>` avec la
stratégie ci-dessous (son seul bucket, sans droit de supprimer une version), puis une clé
d'accès, remise dans un paquet `.kura` chiffré (AES-256-GCM, PBKDF2-SHA256) :

- le **mot de passe** du paquet s'affiche une seule fois, à transmettre par un autre chemin
  que le fichier ;
- le **fichier** se télécharge une seule fois, dans les 30 minutes, et s'ouvre sur le poste
  pendant 72 heures ; la console ne garde pas le secret ;
- sur le poste, `kura-agent import fichier.kura` (kura-agent 0.5 ou plus récent, console
  d'administration) essaie la clé auprès de Wasabi avant de remplacer l'ancienne ;
- une fois la sauvegarde suivante réussie, *Confirmer l'installation* : la console désactive
  les clés qu'elle avait créées avant pour ce poste ; une clé désactivée reste réactivable,
  et devient supprimable après 7 jours. Une ancienne clé créée à la main dans Wasabi se
  désactive dans la console Wasabi (la console n'a de droits que sur les utilisateurs `kura-*`).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListerSonBucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::acme-srv01"
      ]
    },
    {
      "Sid": "LireEcrireSonBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": [
        "arn:aws:s3:::acme-srv01/*"
      ]
    }
  ]
}
```

La vue d'ensemble signale une clé remise depuis plus de 3 jours sans confirmation, et une
clé de plus de 90 jours (rotation due).

**Limite du mode gouvernance.** La console peut modifier les stratégies : compromise, elle
pourrait finir par s'ouvrir le droit de supprimer des versions verrouillées en gouvernance.
Seul le mode conformité (aucun contournement possible, compte racine compris) protège aussi
contre la console elle-même, au prix de ne jamais pouvoir effacer avant échéance.

## Sécurité

- **Écoute locale uniquement** (`127.0.0.1`) et contrôle de l'en-tête `Host` : une page
  d'un autre site qui ferait pointer un nom de domaine vers la machine (DNS rebinding)
  est refusée.
- **Nom d'hôte aléatoire** à chaque lancement (`kura-<aléa>.localhost`) : un cookie ne
  tient pas compte du port, et un cookie posé pour `127.0.0.1` serait aussi envoyé à
  tout autre service local (serveur de développement, page servie par un autre
  utilisateur de la machine). Sous un nom que lui seul connaît, le cookie de session ne
  part que vers la console. Avec `--plain-host`, cette protection disparaît : ne pas
  visiter d'autre service local pendant que la console est déverrouillée.
- **Clé d'administration chiffrée** dans le trousseau du système (Gestionnaire
  d'identification Windows, Trousseau macOS, Secret Service sous Linux) : AES-256-GCM,
  clé dérivée du mot de passe maître par PBKDF2-SHA256 (600 000 itérations). La clé
  Wasabi n'est déchiffrée qu'en mémoire, tant que la console est déverrouillée.
- **Une seule session** : cookie `HttpOnly`, `SameSite=Strict` ; jeton anti-CSRF sur
  chaque formulaire ; contrôle de l'origine des requêtes ; politique de sécurité du
  contenu sans script en ligne ; page non intégrable dans un cadre.
- **Verrouillage** après 30 minutes d'inactivité, ou par le bouton *Verrouiller* : la
  console abandonne le client Wasabi et annule toutes les tâches en cours. Go ne permet
  pas d'effacer la mémoire de façon garantie : une copie de la clé peut y subsister
  jusqu'à ce que le ramasse-miettes la réutilise.
- **Mots de passe** : un essai à la fois, 1 s d'attente après un échec, puis blocage
  après 5 échecs (1 minute, doublé à chaque nouveau blocage, 1 h au plus).
- **Mot de passe maître oublié** : `kura-ctl --reset` efface la clé du trousseau ; il
  suffit de la ressaisir avec un nouveau mot de passe. Les données de la base
  (buckets, historique, journal) sont conservées.

**Linux** : la console a besoin d'un service de trousseau (Secret Service : GNOME
Keyring, KWallet…). Sur un serveur sans interface ou sous WSL, elle le signale dès la
configuration.

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

Essai dans un vrai navigateur (Chromium, avec Playwright installé), sur un compte
Wasabi factice :

```sh
KURA_E2E=/tmp/kura-e2e go test -count=1 -run TestServeForBrowser ./internal/web/ &
node scripts/e2e-browser.js /tmp/kura-e2e
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
