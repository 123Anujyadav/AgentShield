import { runReferenceAgent } from "./cli.js";

process.exitCode = await runReferenceAgent(process.argv.slice(2), { env: process.env, out: (line) => console.log(line), err: (line) => console.error(line) });
