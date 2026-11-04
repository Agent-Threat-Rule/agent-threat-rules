/**
 * No-op. This used to fetch data/*.json from GitHub after load and replace
 * the numbers on the page, so a reader could see figures that matched no
 * build and carried no date. Every figure now comes from the build and the
 * page says when it was generated. Kept so existing pages still compile.
 */
export function StatsHydrator() {
  return null;
}
