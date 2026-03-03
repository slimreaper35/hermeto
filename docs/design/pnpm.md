# pnpm

This document describes the design of the `pnpm` package manager support in Hermeto.

## Overview

`pnpm` is a fast, disk space-efficient package manager for JavaScript and TypeScript.

### pnpm vs npm

`pnpm` uses a unique hard links and symbolic links approach to organize `node_modules`,
which is very different from the traditional flat `npm` structure.

All package files are stored only **once** in a global content-addressable store.
Only direct dependencies of a project appear as **top-level directories** inside
`node_modules`. By using this approach, it is impossible to use modules that are
not specified in the `package.json` file. Example:

```text
node_modules
├── foo@1.0.0 -> .pnpm/foo@1.0.0/node_modules/foo
├── bar@1.0.0 -> .pnpm/bar@1.0.0/node_modules/bar
└── .pnpm
    ├── foo@1.0.0
    │   └── node_modules
    │       └── foo
    │           ├── index.js     →  <store>/…/001  (hard link)
    │           └── package.json →  <store>/…/002  (hard link)
    └── bar@1.0.0
        └── node_modules
            └── bar
                ├── index.js     →  <store>/…/003 (hard link)
                └── package.json →  <store>/…/004 (hard link)
```

For more details, see [pnpm node_modules structure](https://pnpm.io/symlinked-node-modules-structure).

### Installation

Refer to the [pnpm installation guide](https://pnpm.io/installation) for the instructions.

### Project structure

A minimal `pnpm` project could have the following structure:

```text
├── node_modules
├── pnpm-lock.yaml
├── package.json
└── index.js
```

- `pnpm-lock.yaml` is a lockfile that contains the resolved versions of the dependencies
- `package.json` is the manifest file of a package that contains the package metadata

Compared to an `npm` project, the `package.json` file has an additional `packageManager`
field that specifies the package manager and version used to install the dependencies.

```jsonc
{
  "name": "foo",
  "version": "1.0.0",
  "packageManager": "pnpm@10.30.3"
  // other fields
}
```

## Dependencies

`pnpm` supports installing packages from various sources. See the
[Supported package sources](https://pnpm.io/package-sources) page.

### Package sources

- npm registry
- JSR registry
- workspace packages
- local file system
- remote tarballs
- git repositories

### devDependencies

```shell
pnpm add axios@1.13.6 --save-dev
```

The `package.json` file will contain the following:

```json
{
  "devDependencies": {
    "axios": "1.13.6"
  }
}
```

<details>
    <summary>pnpm-lock.yaml</summary>

```yaml
lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      axios:
        specifier: 1.13.6
        version: 1.13.6

# ...
snapshots:

# ...
  axios@1.13.6:
    dependencies:
      follow-redirects: 1.15.11
      form-data: 4.0.5
      proxy-from-env: 1.1.0
    transitivePeerDependencies:
      - debug
```

</details>

### optionalDependencies

```shell
pnpm add axios@1.13.6 --save-optional
```

**NOTE:** Hermeto will skip the optional dependencies. If a package is marked as
optional, it will contain the `optional: true` flag in the lockfile snapshots section
as shown in the example below.

The `package.json` file will contain the following:

```json
{
  "optionalDependencies": {
    "axios": "1.13.6"
  }
}
```

<details>
    <summary>pnpm-lock.yaml</summary>

```yaml
lockfileVersion: '9.0'

importers:

  .:
    optionalDependencies:
      axios:
        specifier: 1.13.6
        version: 1.13.6
# ...

snapshots:

# ...
  axios@1.13.6:
    dependencies:
      follow-redirects: 1.15.11
      form-data: 4.0.5
      proxy-from-env: 1.1.0
    transitivePeerDependencies:
      - debug
    optional: true
```

</details>

### peerDependencies

```shell
pnpm add axios@1.13.6 --save-peer
```

**NOTE:** `--save-peer` option will add the specified packages to `peerDependencies`
and install them as dev dependencies. In other word, the `peerDependencies` field
is a subset of the `devDependencies` field.

The `package.json` file will contain the following:

```json
{
  "devDependencies": {
    "axios": "1.13.6"
  },
  "peerDependencies": {
    "axios": "1.13.6"
  }
}
```

<details>
    <summary>pnpm-lock.yaml</summary>

```yaml
lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      axios:
        specifier: 1.13.6
        version: 1.13.6

# ...
snapshots:

# ...
  axios@1.13.6:
    dependencies:
      follow-redirects: 1.15.11
      form-data: 4.0.5
      proxy-from-env: 1.1.0
    transitivePeerDependencies:
      - debug
```

</details>

## Lockfile format

Hermeto will support **lockfile version 9.0** only. The root keys can be found
in the [pnpm source repository](https://github.com/pnpm/pnpm/blob/main/lockfile/fs/src/sortLockfileKeys.ts#L34).

### packages

By parsing the `packages` section of the lockfile, Hermeto will identify:

### snapshots

TODO

## Implementation

### Prefetching

Hermeto will use a **lockfile parsing** approach.

It will read the `pnpm-lock.yaml` file, extract packages from the `packages` section,
fetch tarballs directly, verify checksums (by converting the SRI from `resolution.integrity`
when present), and inject the lockfile with the local file paths pointing to the
output directory.

### SBOM

### npm registry

### JSR registry

### workspace packages

### local file system

### remote tarballs

### git repositories

### Proxy support

Hermeto will use the same proxy configuration as the `npm` package manager
(`config.npm.proxy_login`, `config.npm.proxy_password`).

### Hermetic build

Hermeto will prepare the project for offline builds by:

1. downloading all packages to `./hermeto-output/deps/pnpm/<name>-<version>.tgz`
2. patching the lockfile so each package's `resolution.tarball` points to the
   local file: `file://${output_dir}/deps/pnpm/<name>-<version>.tgz`

No environment variables will be needed during the build.
