#!/usr/bin/env node
// Thin Node shim. The real binary ships inside one of the platform-specific
// @pocketshell/<triple> packages, declared as optionalDependencies. npm
// installs only the package whose os/cpu/libc matches the user's machine, so
// by the time this shim runs, exactly one of them is present on disk. We
// resolve its location and exec the binary with the user's argv.
//
// This one file serves both commands this package installs, `thumbdesk` and
// its old name `pocketshell`. The platform packages are shared with the
// `pocketshell` npm package, and keep their @pocketshell names.
//
// Runtime libc detection (musl vs glibc on Linux) mirrors npm's own
// optional-dep filtering, so the package chosen here always matches what
// npm actually installed.

'use strict';

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

// The npm package this shim belongs to, for the reinstall hint.
const WRAPPER = 'thumbdesk';

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

// Where the binary may sit in the platform package, most preferred first. On
// macOS the package carries the app (Thumbdesk.app; PocketShell.app before 1.4.0), and
// the binary is the one inside it: running it from the bundle is what gives
// the daemon its menu-bar item and lets macOS attach permissions to an app.
// Packages built from a release without the app carry the plain binary, under
// the old name today and possibly the new one later.
function binaryCandidates(pkgRoot) {
  const exe = process.platform === 'win32' ? '.exe' : '';
  const candidates = [];
  if (process.platform === 'darwin') {
    candidates.push(path.join(pkgRoot, 'Thumbdesk.app', 'Contents', 'MacOS', 'thumbdesk'));
    candidates.push(path.join(pkgRoot, 'PocketShell.app', 'Contents', 'MacOS', 'pocketshell'));
  }
  candidates.push(path.join(pkgRoot, 'bin', `thumbdesk${exe}`));
  candidates.push(path.join(pkgRoot, 'bin', `pocketshell${exe}`));
  return candidates;
}

const pkgName = resolvePackageName();
if (!pkgName) {
  console.error(
    `thumbdesk: no prebuilt binary for ${process.platform}/${process.arch}.\n` +
      `Supported: darwin/arm64, linux/x64 (gnu+musl), linux/arm64, win32/x64.\n` +
      `See https://thumbdesk.com for manual install options.`
  );
  process.exit(1);
}

let pkgRoot;
try {
  pkgRoot = path.dirname(require.resolve(`${pkgName}/package.json`));
} catch (_) {
  console.error(
    `thumbdesk: platform package ${pkgName} is not installed.\n` +
      `This usually means npm skipped optional dependencies ` +
      `(e.g. --no-optional / --omit=optional).\n` +
      `Reinstall with: npm i -g ${WRAPPER}`
  );
  process.exit(1);
}

const binPath = binaryCandidates(pkgRoot).find((candidate) => fs.existsSync(candidate));
if (!binPath) {
  console.error(
    `thumbdesk: ${pkgName} holds no binary.\n` + `Reinstall with: npm i -g ${WRAPPER}`
  );
  process.exit(1);
}
const result = spawnSync(binPath, process.argv.slice(2), { stdio: 'inherit' });

if (result.error) {
  console.error(`thumbdesk: failed to launch binary: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status == null ? 1 : result.status);
