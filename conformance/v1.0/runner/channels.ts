/**
 * MCP event channels a `scan_target: mcp` payload is presented on.
 *
 * A fixture declares a scan target, not a channel, so the runner materialises
 * the payload once per channel and asks the engine about the batch. A TP
 * fixture passes when the Rule fires on at least one channel; a TN fixture
 * passes only when it fires on none — the same normalisation, applied in both
 * directions, so it cannot be used to launder a false positive.
 *
 * Shared by run-conformance.ts, which builds one event per channel, and by
 * generate-fixtures.ts, which picks only Rules the reference Engine admits on
 * at least one of them.
 */
export const MCP_CHANNELS = [
  'llm_input',
  'llm_output',
  'tool_call',
  'tool_response',
  'multi_agent_message',
] as const;
