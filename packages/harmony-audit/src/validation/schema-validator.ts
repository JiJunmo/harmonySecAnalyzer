import { readFileSync } from "node:fs";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import { AuditInvariantError } from "./invariant-errors.js";

const ajv = new Ajv2020({ allErrors: true, strict: false });
const semantic = compile("component-semantic-result.schema.json");
const exploitability = compile("exploitability-validation-result.schema.json");

function compile(name: string): ValidateFunction {
  const schema = JSON.parse(readFileSync(new URL(`../../resources/schemas/${name}`, import.meta.url), "utf8"));
  return ajv.compile(schema);
}

export function validateSubmissionSchema(kind: string, candidate: unknown): void {
  const validate = kind === "component_semantic_analysis" ? semantic : exploitability;
  if (!validate(candidate)) throw new AuditInvariantError("SCHEMA_INVALID", validate.errors?.map((error) => ({ path: error.instancePath, keyword: error.keyword, message: error.message })));
}
