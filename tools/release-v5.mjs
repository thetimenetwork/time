#!/usr/bin/env node
// Version-5 engine release (time-node-v5, protocol-4 ledger). Same packager,
// checks and refusals as tools/release-v4.mjs; only the profile differs.
// The manifest carries engine:"v5", which is part of its release identity.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CLIENT_FILES as V4_CLIENT_FILES, REQUIRED_FILES as V4_REQUIRED_FILES, SOURCE_DIRS as V4_SOURCE_DIRS, TOOL_FILES as V4_TOOL_FILES,
  collectReleaseFiles as collect, createRelease as create, createSdkDistribution as distribute, cli
} from './release-v4.mjs';
export { safeRelative, validateImagePins, cargoPackages } from './release-v4.mjs';

// v5/Cargo.toml is its own workspace root with its own v5/Cargo.lock. It depends
// on the root crate, pos, bitcoin-bridge, treasury, history and registration,
// and on v4 (which needs v2) as a dev-dependency, so Cargo needs all of them to
// resolve the lockfile. campaign/lib/genesis.mjs is read by v5/tests/fee_genesis_bytes.rs.
export const REQUIRED_FILES = [...V4_REQUIRED_FILES, 'v5/Cargo.toml', 'v5/Cargo.lock', 'campaign/lib/genesis.mjs'];
// Directories are walked recursively for .rs files: v5/src/bin, v5/src/engine and v5/tests/common are included.
export const SOURCE_DIRS = [...V4_SOURCE_DIRS, 'v5/src', 'v5/tests'];
// Packaged when present: v5/tests/production_genesis.rs will read tools/genesis-v5.mjs
// the way fee_genesis_bytes.rs reads campaign/lib/genesis.mjs.
export const OPTIONAL_FILES = ['tools/genesis-v5.mjs'];
export const TOOL_FILES = [...V4_TOOL_FILES, 'tools/release-v5.mjs', 'tools/release-v5.test.mjs', 'tools/fixtures/release-v4-native-linux-final-003b.json'];
// The gateway is the same for both engines; the v4 list already carries every
// module it imports (tools/release-v5.test.mjs checks the import closure).
export const CLIENT_FILES = [...V4_CLIENT_FILES];
export const V5_PROFILE = Object.freeze({engine:'v5',script:'tools/release-v5.mjs',requiredFiles:REQUIRED_FILES,optionalFiles:OPTIONAL_FILES,sourceDirs:SOURCE_DIRS,toolFiles:TOOL_FILES,dockerfiles:['deploy/Dockerfile.v5'],binaries:['time-node-v5','cometbft'],clientFiles:CLIENT_FILES});

export const collectReleaseFiles = (root, extraPaths = []) => collect(root, extraPaths, V5_PROFILE);
export const createRelease = options => create({...options, profile: V5_PROFILE});
export const createSdkDistribution = options => distribute({...options, profile: V5_PROFILE});

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) cli(V5_PROFILE).catch(error => { console.error(error.message); process.exitCode = 1; });
