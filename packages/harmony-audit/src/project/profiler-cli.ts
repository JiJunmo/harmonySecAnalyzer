#!/usr/bin/env node
import { profileProject } from "./profiler.js";
const target = process.argv[2];
if (!target) throw new Error("usage: project-profiler <repository>");
const result = await profileProject(target);
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (result.status !== "complete") process.exitCode = 1;
