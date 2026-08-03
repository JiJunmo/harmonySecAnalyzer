#!/usr/bin/env node
import { AtlasProfile, prepareAtlasIndex } from "../atlas.js";
const target = process.argv[2];
if (!target) throw new Error("usage: atlas-indexer <repository>");
const result = await prepareAtlasIndex(target, new AtlasProfile(process.env.HARMONY_AUDIT_ATLAS ?? "atlas"), process.argv.includes("--force"));
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (!result.ok) process.exitCode = 1;
