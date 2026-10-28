# thumbdesk

Terminal, files and screen access to this machine from the Thumbdesk mobile
app. This npm package installs the `thumbdesk` host-agent CLI as a prebuilt
binary, along with `pocketshell`, its old name, which keeps working.

```sh
npm i -g thumbdesk
thumbdesk pair
thumbdesk daemon start
```

Already installed with `npm i -g pocketshell`? Keep it: that package keeps
updating and installs the `thumbdesk` command too. Don't install both: they
provide the same two commands, so npm refuses the second (`EEXIST`). If you
switch anyway (`npm uninstall -g pocketshell`, then `npm i -g thumbdesk`), run
`thumbdesk daemon stop && thumbdesk daemon start` afterwards: the background
service still starts the binary from the removed package until then.

The binary itself ships in one of the platform-specific packages
(`@pocketshell/darwin-arm64`, `@pocketshell/linux-x64-gnu`,
`@pocketshell/linux-arm64-gnu`, `@pocketshell/linux-x64-musl`,
`@pocketshell/win32-x64-msvc`) and is selected automatically via npm's
`os` / `cpu` / `libc` filtering on `optionalDependencies`.

For the curl-based installer (with Sigstore signature verification) and
full docs, see https://thumbdesk.com.
