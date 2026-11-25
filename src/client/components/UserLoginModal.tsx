import { useState } from "react";
import { api } from "../lib/api";
import { useToast } from "./Toast";
import type { BotSummary, UserLoginStartResponse, UserLoginSubmitResponse } from "../../shared/rpcTypes";

interface UserLoginModalProps {
  onClose: () => void;
  onLoggedIn: () => void;
}

type Step = "phone" | "code";

/** Two-step MTProto login: phone → Telegram sends a code → code (+ optional
 * 2FA password). The session string never leaves the server; only the
 * account row id round-trips through the browser. */
export function UserLoginModal({ onClose, onLoggedIn }: UserLoginModalProps) {
  const toast = useToast();
  const [step, setStep] = useState<Step>("phone");
  const [phone, setPhone] = useState("");
  const [label, setLabel] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
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

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card" style={{ maxWidth: 440, margin: "10vh auto" }} onClick={(e) => e.stopPropagation()}>
        <div className="card-header">
          <div className="card-title">Add User Account</div>
        </div>
        <p className="text-muted" style={{ fontSize: 13, marginBottom: 16 }}>
          Log in with a Telegram <strong>user</strong> phone number (MTProto). A code is sent to that Telegram account.
          Requires <code>TG_API_ID</code> / <code>TG_API_HASH</code> secrets on the Worker — get them at{" "}
          <a href="https://my.telegram.org" target="_blank" rel="noreferrer">my.telegram.org</a>.
        </p>

        {step === "phone" && (
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

        {step === "code" && (
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

        {error && <p style={{ color: "var(--danger)", fontSize: 13, marginBottom: 12 }}>{error}</p>}

        <div className="row">
          {step === "phone" ? (
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
