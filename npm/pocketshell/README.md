# pocketshell

PocketShell is now Thumbdesk. This npm package installs the `thumbdesk`
host-agent CLI as a prebuilt binary, along with `pocketshell`, its old name,
which keeps working.

```sh
npm i -g pocketshell
thumbdesk pair
thumbdesk daemon start
```

New installs can use the `thumbdesk` package instead (`npm i -g thumbdesk`);
it installs the same binary and both commands. Already installed from this
one? Keep it: there is no need to switch, and the two cannot be installed
side by side (`EEXIST`).

The binary itself ships in one of the platform-specific packages
(`@pocketshell/darwin-arm64`, `@pocketshell/linux-x64-gnu`,
`@pocketshell/linux-arm64-gnu`, `@pocketshell/linux-x64-musl`,
`@pocketshell/win32-x64-msvc`) and is selected automatically via npm's
`os` / `cpu` / `libc` filtering on `optionalDependencies`.

For the curl-based installer (with Sigstore signature verification) and
full docs, see https://thumbdesk.com.
