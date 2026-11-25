import type { ParsedBotActivity } from "./updateParser";

export type ErrorReason =
  | "insufficient_permissions"
  | "bot_not_in_chat"
  | "rate_limited"
  | "invalid_request"
  | "unauthorized"
  | "unknown";

export type Result<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      errorCode: number;
      description: string;
      reason: ErrorReason;
      retryAfter?: number;
    };

export type AccountType = "bot" | "user";

export interface BotSummary {
  id: string;
  bot_id: number;
  bot_username: string;
  label: string;
  created_at: number;
  account_type: AccountType;
  phone?: string | null;
}

/** Step 1 of user-account login: request an SMS/Telegram code. */
export interface UserLoginStartRequest {
  phone: string;
  label?: string;
}

export interface UserLoginStartResponse {
  account_id: string;
  phone_code_hash: string;
  phone_code_type: string;
}

/** Step 2 of user-account login: submit the received code (and 2FA password if enabled). */
export interface UserLoginSubmitRequest {
  account_id: string;
  phone: string;
  phone_code_hash: string;
  code: string;
  password?: string;
}

export type UserLoginSubmitResponse = Result<BotSummary> & { needs_password?: boolean };

export interface BotWebhookDiagnostics {
  is_active: boolean;
  url?: string;
  pending_update_count: number;
  last_error_message?: string;
  last_error_date?: number;
}

export interface BotRateLimitDiagnostics {
  is_cooling_down: boolean;
  cooldown_seconds_remaining: number;
  cooldown_until: number | null;
  events_last_24h: number;
}

/** Result of a token check — see handleVerifyBot. */
export interface BotVerifyResult {
  account_type: AccountType;
  phone?: string | null;
  bot_id: number;
  bot_username: string;
  existing_bot_id: string | null;
  active_tasks: TaskSummary[];
  total_tasks_count: number;
  webhook_info?: BotWebhookDiagnostics;
  rate_limit_info?: BotRateLimitDiagnostics;
}

export interface BotInspectionReport {
  account_type: AccountType;
  phone?: string | null;
  bot_id: number;
  bot_username: string;
  clone_worker_tasks: {
    active_count: number;
    tasks: TaskSummary[];
  };
  webhook: BotWebhookDiagnostics;
  polling_session: {
    conflict_detected: boolean;
    message?: string;
  };
  rate_limits: BotRateLimitDiagnostics;
  recent_activities: ParsedBotActivity[];
}

export type TaskScope = "live" | "live_and_backfill" | "backfill_only";
export type BackfillStatus =
  | "not_applicable"
  | "pending"
  | "running"
  | "paused"
  | "complete"
  | "cancelled"
  | "failed";

export interface TaskSummary {
  id: string;
  bot_id: string;
  label: string;
  source_chat_id: string;
  source_chat_title: string | null;
  dest_chat_id: string;
  dest_chat_title: string | null;
  scope: TaskScope;
  live_enabled: boolean;
  backfill_mode: "range" | "lastN" | null;
  start_id: number | null;
  end_id: number | null;
  cursor: number | null;
  total: number | null;
  processed: number;
  failed: number;
  live_processed: number;
  live_failed: number;
  live_skipped: number;
  filter_media_types: string | null;
  filter_min_size_bytes: number | null;
  filter_max_size_bytes: number | null;
  pending_count?: number;
  backfill_status: BackfillStatus;
  pacing_batch_size: number;
  stop_reason: ErrorReason | null;
  stopped_at: number | null;
  rate_limited_until: number | null;
  created_at: number;
}

export interface TaskDetail extends TaskSummary {
  bot_username: string;
  account_type: AccountType;
}

export interface CapabilityEntry {
  key: string;
  label: string;
  available: boolean;
  reason?: string;
}

export interface SourceTaskHistory {
  id: string;
  bot_id: string;
  bot_username: string;
  bot_label: string;
  label: string;
  dest_chat_id: string;
  dest_chat_title: string | null;
  scope: TaskScope;
  backfill_mode: "range" | "lastN" | null;
  start_id: number | null;
  end_id: number | null;
  cursor: number | null;
  total: number | null;
  processed: number;
  failed: number;
  live_processed?: number;
  live_failed?: number;
  backfill_status: BackfillStatus;
  live_enabled: boolean;
  stop_reason: ErrorReason | null;
  stopped_at: number | null;
  created_at: number;
  last_copied_message_id: number | null;
  last_activity_at: number | null;
}

export interface ChatLookupResult {
  chat: { id: number; type: string; title?: string; username?: string };
  accountType: AccountType;
  botStatus: string;
  capabilities: CapabilityEntry[];
  memberCount?: number;
  admins?: Array<{ id: number; name: string; status: string; is_bot: boolean }>;
  pastTasks?: SourceTaskHistory[];
}

// Saved Tasks

export interface SavedTaskSummary {
  id: string;
  task_id: string | null;
  account_id: string | null;
  bot_label: string;
  bot_username: string;
  token_preview: string;
  source_chat_id: string;
  source_chat_title: string | null;
  dest_chat_id: string;
  dest_chat_title: string | null;
  scope: TaskScope;
  backfill_mode: "range" | "lastN" | null;
  start_id: number | null;
  end_id: number | null;
  n: number | null;
  pacing_batch_size: number;
  filter_media_types: string | null;
  filter_min_size_bytes: number | null;
  filter_max_size_bytes: number | null;
  created_at: number;
}

export interface SavedTaskWithToken extends SavedTaskSummary {
  bot_token: string;
}

// Authentication

export type AuthMode = "enforced" | "open";
export type AuthSource = "env" | "d1" | "none";

export interface AuthStatusResponse {
  mode: AuthMode;
  source: AuthSource;
  authenticated: boolean;
}

export interface AuthLoginResponse {
  token: string;
}
