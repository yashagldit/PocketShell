# pocketshell

Secure mobile-to-host terminal access. This npm package installs the
`pocketshell` host-agent CLI as a prebuilt binary.

```sh
npm i -g pocketshell
pocketshell pair
pocketshell daemon start
```

The binary itself ships in one of four platform-specific packages
(`@pocketshell/darwin-arm64`, `@pocketshell/linux-x64-gnu`,
`@pocketshell/linux-arm64-gnu`, `@pocketshell/linux-x64-musl`) and is
selected automatically via npm's `os` / `cpu` / `libc` filtering on
`optionalDependencies`.

For the curl-based installer (with Sigstore signature verification) and
full docs, see https://pocketshell.app.
