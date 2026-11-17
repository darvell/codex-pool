import type { AccountStats, Provider } from "./types";

// Burn is account throughput, not API-price-equivalent tokens. Codex-style
// usage includes cache reads inside input_tokens; Anthropic reports them as a
// separate field, so only Claude needs the cached count added explicitly.
export function tokenThroughput(row: { account_type: Provider | "unknown"; input_tokens: number; cached_tokens: number; output_tokens: number }) {
  return row.input_tokens + row.output_tokens + (row.account_type === "claude" ? row.cached_tokens : 0);
}


export function accountThroughput(account: AccountStats) {
  return tokenThroughput({
    account_type: account.type,
    input_tokens: account.total_input_tokens,
    cached_tokens: account.total_cached_tokens,
    output_tokens: account.total_output_tokens,
  });
}
