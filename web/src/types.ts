export type Provider = "codex" | "claude" | "gemini" | "antigravity" | "kimi" | "minimax" | "zai" | "xiaomi" | "grok";

export interface FriendSession {
  public_url: string;
  origin_id: string;
  download_token: string;
  auth_json: string;
  gemini_auth_json: string;
  gemini_api_key: string;
  claude_api_key: string;
  pi_models_json: string;
  cute_code_settings_json: string;
}

export interface AccountStats {
  id: string;
  type: Provider;
  plan_type: string;
  status: "healthy" | "degraded" | "cooldown" | "dead";
  penalty: number;
  primary_window_used_pct: number;
  secondary_window_used_pct: number;
  primary_window_available: boolean;
  secondary_window_available: boolean;
  primary_reset_minutes: number;
  secondary_reset_minutes: number;
  primary_window_minutes: number;
  secondary_window_minutes: number;
  primary_pace_ratio: number;
  secondary_pace_ratio: number;
  account_added_at?: string;
  total_input_tokens: number;
  total_cached_tokens: number;
  total_output_tokens: number;
  total_reasoning_tokens: number;
  total_billable_tokens: number;
  cache_hit_rate_pct: number;
  score: number;
  score_tooltip?: string;
  is_primary: boolean;
  subscription_cost_monthly: number;
  subscription_spend: number;
  subscription_billing_cycles: number;
  subscription_label: string;
  api_cost_estimate: number;
  api_cost_last_30d: number;
  roi: number;
  reset_credits_available?: number;
}

export interface PoolStats {
  total_accounts: number;
  active_accounts: number;
  total_pool_users: number;
  last_24h_tokens: number;
  accounts: AccountStats[];
  aggregate: {
    total_input_tokens: number;
    total_cached_tokens: number;
    total_output_tokens: number;
    total_reasoning_tokens: number;
    total_billable_tokens: number;
    overall_cache_hit_rate_pct: number;
    total_api_cost: number;
    total_subscription_cost: number;
    total_subscription_monthly: number;
    overall_roi: number;
  };
  generated_at: string;
}

export interface ModelDescriptor {
  id: string;
  name?: string;
  protocol: string;
  contextWindow?: number;
  description?: string;
  provider: Provider;
  upstream_id?: string;
  max_output_tokens?: number;
  protocols?: string[];
  modalities?: string[];
  capabilities?: Record<string, boolean>;
  supported_mime_types?: string[];
  recommended?: boolean;
  quota_remaining_fraction?: number;
  aliases?: string[];
  supporting_accounts?: number;
  available_accounts?: number;
  available_now: boolean;
  next_reset_at?: string;
  stale?: boolean;
}

export interface ModelCatalog {
  models: ModelDescriptor[];
}

export interface SignalEconomicsPoint {
  date: string;
  daily_api_value: number;
  cumulative_api_value: number;
  cumulative_subscription_spend: number;
  provider_api_value: Record<string, number>;
}

export interface HourlyUsage {
  hour: string;
  account_type: Provider | "unknown";
  input_tokens: number;
  cached_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  billable_tokens: number;
  request_count: number;
}

export interface OriginWeeklyUsage {
  week_start: string;
  origin_id: string;
  account_id: string;
  account_type: Provider | "unknown";
  input_tokens: number;
  cached_tokens: number;
  output_tokens: number;
  reasoning_tokens: number;
  billable_tokens: number;
  request_count: number;
}

export interface SignalAnalytics {
  generated_at: string;
  origin_data_since: string;
  economics: SignalEconomicsPoint[];
  hourly: HourlyUsage[];
  origin_weekly: OriginWeeklyUsage[];
}

export interface AdminAccount {
  id: string;
  public_id: string;
  type: Provider;
  plan_type: string;
  disabled: boolean;
  dead: boolean;
  inflight: number;
  expires_at?: string;
  last_refresh?: string;
  penalty: number;
  score: number;
  score_tooltip?: string;
  is_primary: boolean;
  usage: Record<string, unknown>;
  totals: Record<string, number>;
}
