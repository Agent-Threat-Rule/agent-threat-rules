import { buildRuleIndex, ruleIndexToCsv } from "@/lib/rule-index";

export const dynamic = "force-static";

export async function GET() {
  return new Response(ruleIndexToCsv(await buildRuleIndex()), {
    headers: { "Content-Type": "text/csv; charset=utf-8" },
  });
}
