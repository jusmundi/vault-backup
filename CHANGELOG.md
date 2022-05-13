# Changelog

<!-- markdown-link-check-disable -->

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# Table of contents

// spell-checker:disable

<!-- toc -->

  * [Size 🌈](#size-%F0%9F%8C%88)
- [[Unreleased]](#unreleased)
- [[0.0.2] - TODO](#002---todo)
- [[0.0.1] - 2022-11-05](#001---2022-11-05)
  * [Added](#added)
  * [Updated](#updated)
  * [Remove](#remove)

<!-- tocstop -->

// spell-checker:enable

### Size 🌈

// cSpell:words vault-backup

## [Unreleased]

<!--lint disable no-undefined-references-->

## [0.0.2] - TODO

## [0.0.1] - 2022-11-05

python:3

```bash
docker build --network=host -t "${DOCKER_ORGANISATION}/vault-backup:0.0.1" --squash .
docker push ${DOCKER_ORGANISATION}/vault-backup:0.0.1
```

### Added

- Add vault_handler.py

### Updated

- None

### Remove

- None

`docker run -it -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro -v /var/run/docker.sock:/var/run/docker.sock --entrypoint /bin/bash ${DOCKER_ORGANISATION}/vault-backup:0.0.1`

```bash
export VAULT_ADDR=${VAULT_ADDR:-"http://vault:8200"}
export ROLE_ID=${ROLE_ID:-"1234"}
export SECRET_ID=${SECRET_ID:-"1234"}
export VAULT_PREFIX=${VAULT_PREFIX:-"gitlab"}
export ENCRYPTION_KEY="XXX"

python3 -b vault_handler.py dump --encrypt

docker run --network=host --env VAULT_ADDR="${VAULT_ADDR}" --env ROLE_ID="${ROLE_ID}" --env SECRET_ID="${SECRET_ID}" --env VAULT_PREFIX="${VAULT_PREFIX}" --env ENCRYPTION_KEY="${ENCRYPTION_KEY}" --name test-vault-backup --rm jusmundi/vault-backup:latest print
```

<!-- markdown-link-check-enable -->
