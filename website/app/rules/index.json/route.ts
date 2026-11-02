import { buildRuleIndex } from "@/lib/rule-index";

export const dynamic = "force-static";

export async function GET() {
  return Response.json(await buildRuleIndex());
}
