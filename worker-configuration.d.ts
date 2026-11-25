interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  ADMIN_PASSWORD?: string;
  AUTH_SECRET?: string;
  // Telegram app credentials for user-account (MTProto) login.
  // Set as secrets: wrangler secret put TG_API_ID / TG_API_HASH
  TG_API_ID?: string;
  TG_API_HASH?: string;
}
