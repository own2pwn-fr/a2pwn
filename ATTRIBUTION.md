# Attribution

a2pwn's seed skills *reference* payloads and techniques from external security-knowledge projects,
vendored as pinned git submodules under `vendor/` (never copied into this repo). Credit and license
terms below.

| Source | License | Use in a2pwn |
|--------|---------|--------------|
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | MIT | Payload lists referenced by `skills/**/payloads.yaml` |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | Templates run via the `nuclei` tool wrapper |
| [HackTricks](https://github.com/HackTricks-wiki/hacktricks) | CC-BY-SA 4.0 | Methodology references (quarantined under `skills/_sa/`) |

## CC-BY-SA 4.0 notice (HackTricks)

Any skill text derived from HackTricks is kept under `skills/_sa/` with its own header linking back to
the source page and noting modifications, per CC-BY-SA 4.0 (attribution + share-alike). a2pwn does not
redistribute HackTricks content verbatim in the main skill tree; it links to the vendored submodule.

## a2pwn itself

a2pwn is licensed AGPL-3.0-or-later (see `LICENSE`). Vendored submodules retain their own licenses.
