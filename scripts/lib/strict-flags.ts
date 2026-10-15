/**
 * `--flag value` pairs, strictly: an unknown or misspelled flag, a stray
 * argument, a repeated flag, or a flag without a value is an error rather than
 * something to skip. A workflow that drops or misspells a flag must fail on the
 * runner and in the tests that feed it the workflow's own argv, not run with a
 * default nobody chose.
 */
export function parseFlagPairs(
  argv: readonly string[],
  known: ReadonlySet<string>,
  usageError: (message: string) => Error,
): ReadonlyMap<string, string> {
  const values = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i] ?? "";
    if (!known.has(flag)) throw usageError(`unknown argument: ${flag}`);
    if (values.has(flag)) throw usageError(`${flag} given more than once`);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--") || value.trim() === "") {
      throw usageError(`${flag} requires a value`);
    }
    values.set(flag, value);
  }
  return values;
}
