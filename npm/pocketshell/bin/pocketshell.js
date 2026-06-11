#!/usr/bin/env node
// Thin Node shim. The real `pocketshell` binary ships inside one of the
// platform-specific @pocketshell/<triple> packages, declared as
// optionalDependencies. npm installs only the package whose os/cpu/libc
// matches the user's machine, so by the time this shim runs, exactly one
// of them is present on disk. We resolve its location and exec the binary
// with the user's argv.
//
// Runtime libc detection (musl vs glibc on Linux) mirrors npm's own
// optional-dep filtering, so the package chosen here always matches what
// npm actually installed.

'use strict';

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

function detectLinuxLibc() {
  try {
    if (fs.existsSync('/etc/alpine-release')) return 'musl';
    if (
      fs.existsSync('/lib/ld-musl-x86_64.so.1') ||
      fs.existsSync('/lib/ld-musl-aarch64.so.1')
    ) {
      return 'musl';
    }
  } catch (_) {}
  return 'gnu';
}

function resolvePackageName() {
  const { platform, arch } = process;
  if (platform === 'darwin' && arch === 'arm64') return '@pocketshell/darwin-arm64';
  if (platform === 'linux' && arch === 'arm64') return '@pocketshell/linux-arm64-gnu';
  if (platform === 'linux' && arch === 'x64') {
    return detectLinuxLibc() === 'musl'
      ? '@pocketshell/linux-x64-musl'
      : '@pocketshell/linux-x64-gnu';
  }
  if (platform === 'win32' && arch === 'x64') return '@pocketshell/win32-x64-msvc';
  return null;
}

const pkgName = resolvePackageName();
if (!pkgName) {
  console.error(
    `pocketshell: no prebuilt binary for ${process.platform}/${process.arch}.\n` +
      `Supported: darwin/arm64, linux/x64 (gnu+musl), linux/arm64, win32/x64.\n` +
      `See https://pocketshell.app for manual install options.`
  );
  process.exit(1);
}

let pkgRoot;
try {
  pkgRoot = path.dirname(require.resolve(`${pkgName}/package.json`));
} catch (_) {
  console.error(
    `pocketshell: platform package ${pkgName} is not installed.\n` +
      `This usually means npm skipped optional dependencies ` +
      `(e.g. --no-optional / --omit=optional).\n` +
      `Reinstall with: npm i -g pocketshell`
  );
  process.exit(1);
}

const binName = process.platform === 'win32' ? 'pocketshell.exe' : 'pocketshell';
const binPath = path.join(pkgRoot, 'bin', binName);
const result = spawnSync(binPath, process.argv.slice(2), { stdio: 'inherit' });

if (result.error) {
  console.error(`pocketshell: failed to launch binary: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status == null ? 1 : result.status);
