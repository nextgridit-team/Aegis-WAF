export type BotChallenge = {
  enabled: boolean;
  score_threshold: number;
  clearance_minutes: number;
  risk_requests_per_second: number;
  risk_burst: number;
};
export type BotDecision = {
  score: number;
  threshold: number;
  reasons?: string[];
  decision?: string;
};
export const defaultBotChallenge = (): BotChallenge => ({
  enabled: false,
  score_threshold: 60,
  clearance_minutes: 30,
  risk_requests_per_second: 25,
  risk_burst: 50,
});
export function botChallengeMarkup(value?: Partial<BotChallenge>) {
  const s = { ...defaultBotChallenge(), ...value };
  const number = (name: string, label: string, v: number, max: number) =>
    `<label class="field">${label}<input type="number" name="${name}" min="1" max="${max}" required value="${v}"></label>`;
  return `<details class="advanced"><summary>Selective bot verification</summary><label class="check"><input type="checkbox" name="bot_challenge_enabled" ${s.enabled ? "checked" : ""}><span>Challenge suspected bots with self-hosted CAPTCHA</span></label><p class="muted">Ordinary requests pass without a challenge. Suspicion combines scanner/headless signals, header inconsistencies, sensitive-path probes and bounded request-frequency signals. Observe records the decision; Block challenges clients at the threshold.</p><div class="form-grid">${number("bot_score_threshold", "Bot suspicion threshold", s.score_threshold, 100)}${number("bot_clearance_minutes", "Bot clearance duration (minutes)", s.clearance_minutes, 120)}${number("bot_risk_rate", "Request-frequency signal rate / second", s.risk_requests_per_second, 100000)}${number("bot_risk_burst", "Request-frequency signal burst", s.risk_burst, 1000000)}</div><small>Image and audio CAPTCHA run entirely on Aegis. HTTPS is required. Successful verification grants bounded application/client clearance for bot challenges; flood, CIDR/Geo and signatures still apply. API clients receive a verification-required JSON response, and unsafe requests are never automatically replayed. Request-frequency signals are currently per replica.</small></details>`;
}
export function readBotChallenge(f: FormData): BotChallenge {
  return {
    enabled: f.has("bot_challenge_enabled"),
    score_threshold: Number(f.get("bot_score_threshold") || 60),
    clearance_minutes: Number(f.get("bot_clearance_minutes") || 30),
    risk_requests_per_second: Number(f.get("bot_risk_rate") || 25),
    risk_burst: Number(f.get("bot_risk_burst") || 50),
  };
}
