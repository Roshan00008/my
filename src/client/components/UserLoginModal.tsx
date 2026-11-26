import { useState } from "react";
import { api } from "../lib/api";
import { useToast } from "./Toast";
import type { BotSummary, UserLoginStartResponse, UserLoginSubmitResponse } from "../../shared/rpcTypes";

interface UserLoginModalProps {
  onClose: () => void;
  onLoggedIn: () => void;
}

type Step = "phone" | "code";
type Mode = "phone" | "session";

/** Two ways to add a user account: phone → Telegram sends a code → code (+ optional
 *  2FA password), or paste a Telethon StringSession directly. The session string
 *  never leaves the server; only the account row id round-trips through the browser. */
export function UserLoginModal({ onClose, onLoggedIn }: UserLoginModalProps) {
  const toast = useToast();
  const [mode, setMode] = useState<Mode>("phone");
  const [step, setStep] = useState<Step>("phone");
  const [phone, setPhone] = useState("");
  const [label, setLabel] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [sessionString, setSessionString] = useState("");
  const [accountId, setAccountId] = useState("");
  const [phoneCodeHash, setPhoneCodeHash] = useState("");
  const [codeType, setCodeType] = useState("");
  const [needsPassword, setNeedsPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setError(null);
    const res = await api.post<UserLoginStartResponse>("/api/accounts/user/start", {
      phone: phone.trim(),
      label: label.trim() || undefined,
    });
    setBusy(false);
    if (res.ok) {
      setAccountId(res.data.account_id);
      setPhoneCodeHash(res.data.phone_code_hash);
      setCodeType(res.data.phone_code_type);
      setStep("code");
    } else {
      setError(res.description);
    }
  }

  async function submit() {
    setBusy(true);
    setError(null);
    const res = (await api.post<BotSummary>("/api/accounts/user/submit", {
      account_id: accountId,
      phone: phone.trim(),
      phone_code_hash: phoneCodeHash,
      code: code.trim(),
      password: password || undefined,
    })) as UserLoginSubmitResponse;
    setBusy(false);
    if (res.ok) {
      toast.show("success", `User account ${res.data.label} connected`);
      onLoggedIn();
    } else if (res.needs_password && !password) {
      setNeedsPassword(true);
      setError("This account has two-factor authentication — enter your password.");
    } else {
      setError(res.description);
    }
  }

  async function importSession() {
    setBusy(true);
    setError(null);
    const res = await api.post<BotSummary>("/api/accounts/user/session", {
      session_string: sessionString.trim(),
      label: label.trim() || undefined,
    });
    setBusy(false);
    if (res.ok) {
      toast.show("success", `User account ${res.data.label} connected`);
      onLoggedIn();
    } else {
      setError(res.description);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card" style={{ maxWidth: 440, margin: "10vh auto" }} onClick={(e) => e.stopPropagation()}>
        <div className="card-header">
          <div className="card-title">Add User Account</div>
        </div>
        <p className="text-muted" style={{ fontSize: 13, marginBottom: 12 }}>
          {mode === "phone" ? (
            <>
              Log in with a Telegram <strong>user</strong> phone number (MTProto). A code is sent to that Telegram account.
              Requires <code>TG_API_ID</code> / <code>TG_API_HASH</code> secrets on the Worker — get them at{" "}
              <a href="https://my.telegram.org" target="_blank" rel="noreferrer">my.telegram.org</a>.
            </>
          ) : (
            <>
              Paste a Telegram <strong>session string</strong> (Telethon StringSession, starts with <code>1</code>) — no code
              or 2FA needed. Generate one with a MTProto client library, e.g. Telethon or Pyrogram.
            </>
          )}
        </p>

        <div className="row" style={{ marginBottom: 14, gap: 8 }}>
          <button
            className={mode === "phone" ? "btn btn-primary" : "btn btn-secondary"}
            onClick={() => { setMode("phone"); setError(null); }}
          >
            Phone code
          </button>
          <button
            className={mode === "session" ? "btn btn-primary" : "btn btn-secondary"}
            onClick={() => { setMode("session"); setError(null); }}
          >
            Session string
          </button>
        </div>

        {mode === "phone" && step === "phone" && (
          <>
            <input
              className="input"
              style={{ marginBottom: 10 }}
              placeholder="Phone (+15551234567)"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              autoFocus
            />
            <input
              className="input"
              style={{ marginBottom: 14 }}
              placeholder="Label (optional)"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
            />
          </>
        )}

        {mode === "phone" && step === "code" && (
          <>
            <p className="text-muted" style={{ fontSize: 13, marginBottom: 10 }}>
              Code sent to <strong>{phone}</strong> via {codeType.replace("auth.sentCodeType", "")}.
            </p>
            <input
              className="input"
              style={{ marginBottom: 10 }}
              placeholder="Login code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoFocus
            />
            {needsPassword && (
              <input
                className="input"
                style={{ marginBottom: 14 }}
                type="password"
                placeholder="2FA password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            )}
          </>
        )}

        {mode === "session" && (
          <>
            <textarea
              className="input"
              style={{ marginBottom: 10, minHeight: 110, resize: "vertical", fontFamily: "monospace", fontSize: 12 }}
              placeholder="Session string (1AAAA...)"
              value={sessionString}
              onChange={(e) => setSessionString(e.target.value)}
              autoFocus
            />
            <input
              className="input"
              style={{ marginBottom: 14 }}
              placeholder="Label (optional)"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
            />
          </>
        )}

        {error && <p style={{ color: "var(--danger)", fontSize: 13, marginBottom: 12 }}>{error}</p>}

        <div className="row">
          {mode === "session" ? (
            <button className="btn btn-primary" disabled={busy || !sessionString.trim()} onClick={importSession}>
              {busy ? "Importing…" : "Import session"}
            </button>
          ) : step === "phone" ? (
            <button className="btn btn-primary" disabled={busy || !phone.trim()} onClick={start}>
              {busy ? "Sending code…" : "Send code"}
            </button>
          ) : (
            <button className="btn btn-primary" disabled={busy || !code.trim()} onClick={submit}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
          )}
          <button className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
