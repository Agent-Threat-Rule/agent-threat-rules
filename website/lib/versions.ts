import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The three version labels the site shows, kept apart because they move apart:
 *
 *   spec      — the written core specification, versioned in SPEC.md's own
 *               header ("Version: 1.0.1"). It changes only when the normative
 *               text changes.
 *   npm       — the latest agent-threat-rules release on the npm registry,
 *               read once before the build (scripts/fetch-npm-version.mjs). The release commit can land on main before
 *               the publish job runs, so package.json on main can be ahead of
 *               what `npm install` returns; quoting package.json as "npm" would
 *               name a version nobody can install yet.
 *   generated — the date this page was built. The other two are true as of
 *               that date and no later.
 *
 * A single "version" used to stand for all three (package.json, shown as the
 * spec version on /spec, while the footer still hard-coded 3.5.0).
 */

const REPO_ROOT = join(process.cwd(), "..");
export const NPM_PACKAGE = "agent-threat-rules";
export const NPM_PACKAGE_URL = `https://www.npmjs.com/package/${NPM_PACKAGE}`;
export const SPEC_SOURCE_URL = "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SPEC.md";
const NPM_LATEST_FILE = join(process.cwd(), ".generated", "npm-latest.json");
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

export interface CoreSpecVersion {
  /** "1.0.1", or "unversioned" when SPEC.md has no Version line. */
  version: string;
  /** SPEC.md "Status:" line, e.g. "Draft". */
  status: string;
  /** SPEC.md "Date:" line (YYYY-MM-DD), or "" when absent. */
  date: string;
}

function headerField(text: string, field: string): string | null {
  const m = new RegExp(`^${field}:\\s*(.+?)\\s*$`, "m").exec(text);
  return m ? m[1] : null;
}

/** Version, status and date from the header of the repo-root SPEC.md. */
export function readCoreSpec(): CoreSpecVersion {
  try {
    const head = readFileSync(join(REPO_ROOT, "SPEC.md"), "utf-8").slice(0, 2000);
    return {
      version: headerField(head, "Version") ?? "unversioned",
      status: headerField(head, "Status") ?? "",
      date: headerField(head, "Date") ?? "",
    };
  } catch {
    return { version: "unversioned", status: "", date: "" };
  }
}

/** Version in the repo-root package.json: the release line of the commit this site was built from. */
export function readPackageVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf-8")) as { version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "unversioned";
  } catch {
    return "unversioned";
  }
}

/**
 * Latest npm version as scripts/fetch-npm-version.mjs recorded it just before
 * the build (or dev server) started; null when it could not read the registry
 * or did not run.
 */
function readNpmLatest(): string | null {
  try {
    const raw = JSON.parse(readFileSync(NPM_LATEST_FILE, "utf-8")) as { version?: unknown };
    return typeof raw.version === "string" && SEMVER.test(raw.version) ? raw.version : null;
  } catch {
    return null;
  }
}

/** UTC date (YYYY-MM-DD) this build generated its pages. */
export const PAGE_GENERATED_AT = new Date().toISOString().slice(0, 10);

export interface VersionLabels {
  spec: CoreSpecVersion;
  /**
   * The version an `npm install` resolves to. When the registry could not be
   * read this is package.json on the built commit and `npmVerified` is false;
   * the label then says so instead of calling it the npm release.
   */
  npm: string;
  npmVerified: boolean;
  /** package.json on the built commit; differs from `npm` while a release awaits publishing. */
  packageVersion: string;
  generatedAt: string;
}

export async function loadVersionLabels(): Promise<VersionLabels> {
  const packageVersion = readPackageVersion();
  const latest = readNpmLatest();
  return {
    spec: readCoreSpec(),
    npm: latest ?? packageVersion,
    npmVerified: latest !== null,
    packageVersion,
    generatedAt: PAGE_GENERATED_AT,
  };
}

/** What to put after `npm install`: pinned when the registry confirmed the version, unpinned otherwise. */
export function npmInstallSpec(labels: VersionLabels): string {
  return labels.npmVerified ? `${NPM_PACKAGE}@${labels.npm}` : NPM_PACKAGE;
}

/** "latest npm release agent-threat-rules@4.2.2", or the package.json version marked unverified when the registry was not read. */
export function npmReleaseText(labels: VersionLabels, zh: boolean): string {
  if (labels.npmVerified) {
    return zh ? `npm 最新版 ${NPM_PACKAGE}@${labels.npm}` : `latest npm release ${NPM_PACKAGE}@${labels.npm}`;
  }
  return zh
    ? `package.json ${labels.packageVersion}(建置時未能確認 npm 版本)`
    : `package.json ${labels.packageVersion} (npm not checked at build time)`;
}
