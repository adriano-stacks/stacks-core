# `nix` flake

Build `stacks-node` and `stacks-signer` by pointing to the `flake.nix` file in
this directory. For instance, from the root directory: `nix build
'./contrib/nix'`.

Other packages exposed by this flake: `stacks-signer`, `stacks-cli`,
`clarity-cli`, `stacks-inspect`, and `block-validation` (see below).

## `block-validation`

[`contrib/tools/block-validation.sh`](../tools/block-validation.sh) wrapped with
every runtime dependency (tmux, aria2, GNU coreutils/findutils, a rust toolchain
to build `stacks-inspect`, a C compiler, ...) on `PATH`, so it runs as-is on
NixOS — no `apt-get`/`rustup` bootstrap. Build and run:

```bash
nix build './contrib/nix#block-validation'
./result/bin/block-validation --help
# or, without producing a ./result symlink:
nix run './contrib/nix#block-validation' -- --help
```

The wrapper sets `SKIP_DEP_INSTALL=1`, which makes the script verify its
dependencies are present rather than trying to install them. You can set the
same variable when running the script directly under any externally-managed
environment.

## Installing `nix`

Follow the [official documentation](https://nix.dev/install-nix) or use the
[Determinate Nix Installer](https://github.com/DeterminateSystems/nix-installer).

## Using `direnv`

If using `direnv`, from the root directory of this repository:

```bash
echo "use flake ./contrib/nix/" > .envrc
direnv allow
```

This will provide a `sh` environment with required dependencies (e.g., `bitcoind`) available.
