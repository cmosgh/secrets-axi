// AWS Secrets Manager and SSM through the `aws` CLI: no SDK dependency, the user's profiles and SSO sessions apply.
import { spawnSync } from "node:child_process";
import { axiError } from "../errors.js";

export interface AwsSpec {
  /** `prod/db`, or `ssm:/app/token` for a Parameter Store entry. */
  id: string;
  /** For a string secret: the variable name. A JSON object secret spreads its top-level keys. */
  name?: string;
}

export function parseAwsSpec(raw: string): AwsSpec {
  const eq = raw.indexOf("=");
  return eq < 0 ? { id: raw } : { id: raw.slice(0, eq), name: raw.slice(eq + 1) };
}

export interface AwsOptions {
  profile?: string;
  region?: string;
  /** Test seam: returns the raw secret string for an id, or throws. */
  fetch?: (spec: AwsSpec, args: string[]) => string;
}

function cliArgs(spec: AwsSpec, options: AwsOptions): string[] {
  const global = [...(options.profile ? ["--profile", options.profile] : []), ...(options.region ? ["--region", options.region] : [])];
  if (spec.id.startsWith("ssm:")) {
    return [...global, "ssm", "get-parameter", "--name", spec.id.slice(4), "--with-decryption", "--query", "Parameter.Value", "--output", "text"];
  }
  return [...global, "secretsmanager", "get-secret-value", "--secret-id", spec.id, "--query", "SecretString", "--output", "text"];
}

function cliFetch(spec: AwsSpec, args: string[]): string {
  const result = spawnSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.error) {
    throw axiError(`aws CLI not available (${result.error.message})`, "SOURCE_ERROR", ["Install the AWS CLI and configure a profile, then retry"]);
  }
  if (result.status !== 0) {
    // AWS error messages name the secret and the error class, never the value.
    const reason = result.stderr.trim().split("\n").pop() ?? "unknown error";
    throw axiError(`aws: ${spec.id}: ${reason}`, "SOURCE_ERROR", ["Check `aws sts get-caller-identity` and the secret id; `aws secretsmanager list-secrets` lists names"]);
  }
  return result.stdout.replace(/\n$/, "");
}

/** Resolve each spec to variables. JSON object → its top-level keys (nested values stringified); anything else needs `id=NAME`. */
export function fetchAwsSecrets(specs: readonly AwsSpec[], options: AwsOptions = {}): { env: Map<string, string>; from: string[] } {
  const env = new Map<string, string>();
  const from: string[] = [];
  const fetch = options.fetch ?? cliFetch;
  for (const spec of specs) {
    const raw = fetch(spec, cliArgs(spec, options));
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = undefined;
    }
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && !spec.name) {
      let count = 0;
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) continue;
        env.set(k, typeof v === "string" ? v : JSON.stringify(v));
        count++;
      }
      from.push(`${spec.id} (${count} keys)`);
      continue;
    }
    if (!spec.name) {
      throw axiError(`aws: ${spec.id} is not a JSON object; name the variable`, "VALIDATION_ERROR", [`Run with \`--aws-secret ${spec.id}=VARIABLE_NAME\``]);
    }
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(spec.name)) throw axiError(`aws: '${spec.name}' is not a variable name`, "VALIDATION_ERROR");
    env.set(spec.name, raw);
    from.push(`${spec.id} → ${spec.name}`);
  }
  return { env, from };
}
