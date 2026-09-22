import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

const REPORT_PATH = 'data/pint-benchmark/pint-eval-report.json';
const LATEST_PATH = 'data/measurements/pint/latest.json';
const LOCKFILE_PATH = 'package-lock.json';
const CORPUS_PATH = 'data/pint-benchmark/pint-corpus.json';
const RUNNER_PATH = 'src/eval/run-pint-benchmark.ts';

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!command) fail('usage: verify-pint-evidence.mjs <preflight|verify|cleanup> [--key value]');
  const options = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    const value = rest[index + 1];
    if (!key?.startsWith('--') || value === undefined) fail(`invalid argument sequence near ${key ?? '<end>'}`);
    options.set(key.slice(2), value);
  }
  return { command, options };
}

function required(options, key) {
  const value = options.get(key);
  if (!value) fail(`missing --${key}`);
  return value;
}

function json(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    fail(`cannot parse ${path}: ${error.message}`);
  }
}

function text(path, label) {
  try {
    const value = readFileSync(path, 'utf8').trim();
    if (!value) fail(`${label} is empty`);
    return value;
  } catch (error) {
    fail(`cannot read ${label} at ${path}: ${error.message}`);
  }
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function timestamp(value, label) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail(`${label} must be an ISO-8601 timestamp`);
  return parsed;
}

function zeroExitCode(value, label) {
  if (!/^(0|[1-9]\d*)$/.test(value)) fail(`${label} must be a non-negative decimal exit code`);
  const code = Number(value);
  if (code !== 0) fail(`${label} must be zero, got ${code}`);
  return code;
}

function git(repo, args) {
  return execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();
}

function repoPath(repo, path) {
  if (isAbsolute(path)) return path;
  return join(repo, path);
}

function normalizedRelative(repo, path) {
  const value = relative(repo, path).split('\\').join('/');
  if (!value || value.startsWith('../') || value === '..') fail(`path escapes repository: ${path}`);
  return value;
}

function slugify(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
}

function canonicalMeasurementFilename(measurement) {
  return `${measurement.measured_at.slice(0, 10)}_${slugify(measurement.source)}-${slugify(measurement.source_version)}_atr-${slugify(measurement.atr_version)}.json`;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function statusEntries(repo) {
  const raw = execFileSync('git', ['status', '--porcelain=v1', '-z'], { cwd: repo });
  const entries = [];
  for (const entry of raw.toString('utf8').split('\0')) {
    if (!entry) continue;
    if (entry.length < 4 || entry[2] !== ' ') fail(`unexpected git status entry: ${JSON.stringify(entry)}`);
    const status = entry.slice(0, 2);
    const path = entry.slice(3);
    if (status.includes('R') || status.includes('C')) fail(`renamed or copied path is not allowed: ${path}`);
    entries.push({ status, path });
  }
  return entries;
}

function inputIdentities(repo, otaVersionPath, nodeVersionPath, npmVersionPath) {
  const paths = [LOCKFILE_PATH, CORPUS_PATH, RUNNER_PATH, 'ota.yaml'];
  return {
    repository_commit: git(repo, ['rev-parse', 'HEAD']),
    rules_tree: git(repo, ['rev-parse', 'HEAD:rules']),
    files: Object.fromEntries(paths.map((path) => [path, sha256(repoPath(repo, path))])),
    ota: json(otaVersionPath),
    runtime: {
      node_version: text(nodeVersionPath, 'Node version'),
      npm_version: text(npmVersionPath, 'npm version'),
    },
  };
}

function assertReportShape(report, start, end, preRunHash) {
  const reportTimestamp = report?.report?.timestamp;
  const reportTime = timestamp(reportTimestamp, 'report.report.timestamp');
  if (reportTime < start || reportTime > end) {
    fail(`report timestamp ${reportTimestamp} is outside the recorded execution window`);
  }
  if (report.report.corpusSize !== 850) fail('report.report.corpusSize must be exactly 850');
  if (report.engine !== 'ATREngine') fail('report.engine must be ATREngine');
  if (!Number.isInteger(report.ruleCount) || report.ruleCount <= 0) fail('report.ruleCount must be a positive integer');

  const confusion = report?.report?.overall?.confusion;
  const values = ['tp', 'fp', 'tn', 'fn'].map((key) => confusion?.[key]);
  if (!values.every((value) => Number.isInteger(value) && value >= 0)) {
    fail('report.report.overall.confusion must contain non-negative integer counts');
  }
  if (values.reduce((sum, value) => sum + value, 0) !== 850) {
    fail('report.report.overall.confusion must sum to 850');
  }

  if (typeof report.regression?.passed !== 'boolean' || !Array.isArray(report.regression?.violations)) {
    fail('report.regression must retain boolean passed and array violations fields');
  }
  if (!report.regression.passed) fail('the freshly generated report records a failed PINT regression');
  if (!preRunHash) fail('missing pre-run report identity');
  return reportTimestamp;
}

function metricProjection(metrics, label) {
  const values = {
    recall: metrics?.recall,
    precision: metrics?.precision,
    f1: metrics?.f1,
    fp_rate: metrics?.fp_rate ?? metrics?.fpRate,
  };
  if (!Object.values(values).every(Number.isFinite)) {
    fail(`${label} must contain finite recall, precision, f1, and fp_rate values`);
  }
  return values;
}

function assertExactJson(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${label} does not reconcile exactly`);
}

function assertMeasurementMetrics(report, latest, measurement) {
  const reportMetrics = metricProjection(report?.report?.overall, 'report.report.overall');
  const latestMetrics = metricProjection(latest?.metrics, 'latest PINT measurement metrics');
  const measurementMetrics = metricProjection(measurement?.metrics, 'generated PINT measurement metrics');
  assertExactJson(latestMetrics, reportMetrics, 'latest PINT measurement metrics and report metrics');
  assertExactJson(measurementMetrics, reportMetrics, 'generated PINT measurement metrics and report metrics');
  assertExactJson(latestMetrics, measurementMetrics, 'latest and generated PINT measurement metrics');
  assertExactJson(
    measurement?.confusion,
    report?.report?.overall?.confusion,
    'generated PINT measurement confusion and report confusion',
  );
}

function preflight(options) {
  const repo = resolve(required(options, 'repo'));
  const reportPath = repoPath(repo, required(options, 'report'));
  const startedAt = required(options, 'started-at');
  const output = required(options, 'output');
  const otaVersionPath = required(options, 'ota-version');
  const nodeVersionPath = required(options, 'node-version');
  const npmVersionPath = required(options, 'npm-version');
  const status = statusEntries(repo);
  if (status.length > 0) fail(`checkout must be clean before PINT execution: ${JSON.stringify(status)}`);

  const report = json(reportPath);
  const reportTimestamp = report?.report?.timestamp;
  const reportTime = timestamp(reportTimestamp, 'committed report timestamp');
  if (reportTime >= timestamp(startedAt, 'started-at')) {
    fail('the committed PINT report is unexpectedly within the current execution window');
  }

  const latestPath = repoPath(repo, LATEST_PATH);
  const preflightEvidence = {
    schema_version: 1,
    kind: 'ota_pint_preflight',
    repository: {
      root: repo,
      clean_worktree: true,
    },
    started_at: startedAt,
    committed_report: {
      path: normalizedRelative(repo, reportPath),
      sha256: sha256(reportPath),
      timestamp: reportTimestamp,
      stale_report_rejected: true,
    },
    committed_latest_measurement: {
      path: LATEST_PATH,
      sha256: sha256(latestPath),
      measured_at: json(latestPath).measured_at,
    },
    inputs: inputIdentities(repo, otaVersionPath, nodeVersionPath, npmVersionPath),
  };
  writeJson(output, preflightEvidence);
}

function verify(options) {
  const repo = resolve(required(options, 'repo'));
  const preflightPath = required(options, 'preflight');
  const endedAt = required(options, 'ended-at');
  const output = required(options, 'output');
  const otaExitCode = zeroExitCode(required(options, 'ota-exit-code'), 'Ota task exit code');
  const atrGateExitCode = zeroExitCode(required(options, 'atr-gate-exit-code'), 'ATR PINT regression gate exit code');
  const preflightEvidence = json(preflightPath);
  if (preflightEvidence.kind !== 'ota_pint_preflight' || preflightEvidence.repository?.clean_worktree !== true) {
    fail('preflight evidence does not establish a clean checkout');
  }

  const reportPath = repoPath(repo, REPORT_PATH);
  const latestPath = repoPath(repo, LATEST_PATH);
  const report = json(reportPath);
  const reportHash = sha256(reportPath);
  if (reportHash === preflightEvidence.committed_report?.sha256) {
    fail('PINT report hash did not change from the rejected committed report');
  }

  const startedAt = preflightEvidence.started_at;
  const reportTimestamp = assertReportShape(
    report,
    timestamp(startedAt, 'preflight started_at'),
    timestamp(endedAt, 'ended-at'),
    preflightEvidence.committed_report?.sha256,
  );

  const latest = json(latestPath);
  if (latest.source !== 'pint' || latest.source_version !== 'v1' || latest.samples !== 850) {
    fail('latest PINT measurement pointer has unexpected source, version, or sample count');
  }
  if (latest.measured_at !== reportTimestamp) fail('latest PINT measurement timestamp differs from the fresh report');
  if (typeof latest.file !== 'string' || !latest.file) fail('latest PINT measurement pointer has no file');

  const measurementRelativePath = `data/measurements/pint/${latest.file}`;
  if (!/^data\/measurements\/pint\/\d{4}-\d{2}-\d{2}_pint-v1_atr-[A-Za-z0-9.-]+\.json$/.test(measurementRelativePath)) {
    fail(`generated measurement path is not a canonical PINT measurement: ${measurementRelativePath}`);
  }
  const measurementPath = repoPath(repo, measurementRelativePath);
  if (!existsSync(measurementPath)) fail(`generated PINT measurement is missing: ${measurementRelativePath}`);
  const measurement = json(measurementPath);
  const packageVersion = json(repoPath(repo, 'package.json')).version;
  if (
    measurement.source !== 'pint'
    || measurement.source_version !== 'v1'
    || measurement.samples !== 850
    || measurement.measured_at !== reportTimestamp
    || measurement.atr_version !== packageVersion
    || measurement.atr_commit !== git(repo, ['rev-parse', '--short', 'HEAD'])
    || !Number.isInteger(measurement.rules_loaded)
    || measurement.rules_loaded <= 0
  ) {
    fail('generated PINT measurement does not reconcile with the checked-out repository state');
  }
  if (
    latest.source !== measurement.source
    || latest.source_version !== measurement.source_version
    || latest.atr_version !== measurement.atr_version
    || latest.atr_version !== packageVersion
  ) {
    fail('latest PINT measurement pointer does not reconcile with the generated measurement');
  }
  if (latest.file !== canonicalMeasurementFilename(measurement)) {
    fail(`generated PINT measurement filename is not canonical: ${latest.file}`);
  }
  assertMeasurementMetrics(report, latest, measurement);

  const status = statusEntries(repo);
  const expected = [
    { status: ' M', path: LATEST_PATH },
    { status: ' M', path: REPORT_PATH },
    { status: '??', path: measurementRelativePath },
  ];
  if (JSON.stringify(status) !== JSON.stringify(expected)) {
    fail(`PINT execution changed paths outside the declared review boundary: ${JSON.stringify(status)}`);
  }

  const evidence = {
    schema_version: 1,
    kind: 'ota_pint_execution_evidence',
    preflight: preflightEvidence,
    execution: {
      selected_contract_task: 'verify:pint',
      selected_command: 'npm run eval:pint',
      ota_exit_code: otaExitCode,
      atr_pint_regression_gate_exit_code: atrGateExitCode,
      ended_at: endedAt,
    },
    output: {
      report: {
        path: REPORT_PATH,
        sha256: reportHash,
        timestamp: reportTimestamp,
        corpus_size: report.report.corpusSize,
        engine: report.engine,
        rule_count: report.ruleCount,
        regression_passed: report.regression.passed,
      },
      latest_measurement: {
        path: LATEST_PATH,
        sha256: sha256(latestPath),
      },
      generated_measurement: {
        path: measurementRelativePath,
        sha256: sha256(measurementPath),
      },
    },
    expected_mutations: status,
  };
  writeJson(output, evidence);
}

function cleanup(options) {
  const repo = resolve(required(options, 'repo'));
  const manifestPath = required(options, 'manifest');
  const output = required(options, 'output');
  const manifest = json(manifestPath);
  if (manifest.kind !== 'ota_pint_execution_evidence') fail('cleanup requires verified PINT evidence');
  const generatedPath = manifest.output?.generated_measurement?.path;
  if (typeof generatedPath !== 'string') fail('verified PINT evidence omits the generated measurement path');

  execFileSync('git', ['restore', '--source=HEAD', '--worktree', '--', REPORT_PATH, LATEST_PATH], {
    cwd: repo,
    stdio: 'inherit',
  });
  rmSync(repoPath(repo, generatedPath), { force: true });

  const status = statusEntries(repo);
  if (status.length > 0) fail(`worktree is not clean after removing expected review outputs: ${JSON.stringify(status)}`);
  writeJson(output, {
    schema_version: 1,
    kind: 'ota_pint_cleanup',
    clean_worktree: true,
    restored_paths: [REPORT_PATH, LATEST_PATH],
    removed_path: generatedPath,
  });
}

try {
  const { command, options } = parseArgs(process.argv.slice(2));
  if (command === 'preflight') preflight(options);
  else if (command === 'verify') verify(options);
  else if (command === 'cleanup') cleanup(options);
  else fail(`unknown command: ${command}`);
} catch (error) {
  console.error(`PINT evidence verification failed: ${error.message}`);
  process.exitCode = 1;
}
