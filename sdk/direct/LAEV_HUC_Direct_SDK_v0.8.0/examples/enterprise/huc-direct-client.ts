/** Minimal TypeScript client for the HUC Direct enterprise API. */
export type HucVerification = {
  result: "VALID" | "INVALID" | "INDETERMINATE";
  hybrid_valid: boolean;
  subject: string;
  certificate_sha256: string;
  utxo_status: "ACTIVE" | "SUPERSEDED" | "REVOKED";
  state_freshness_valid: boolean;
};

export class HucDirectClient {
  constructor(private readonly baseUrl: string, private readonly fetcher: typeof fetch = fetch) {}

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await this.fetcher(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = await response.json();
    if (!response.ok) throw new Error(json.detail ?? `HUC API error ${response.status}`);
    return json as T;
  }

  async verifyBundle(bundle: Uint8Array): Promise<HucVerification> {
    const binary = Array.from(bundle, b => String.fromCharCode(b)).join("");
    return this.post("/v1/credentials/verify", { bundle_b64: btoa(binary) });
  }

  async createChallenge(certificateSha256: string, audience: string, ttlSeconds = 120) {
    return this.post<{ payload: Record<string, unknown>; challenge_id: string }>(
      "/v1/direct/challenges", { certificate_sha256: certificateSha256, audience, ttl_seconds: ttlSeconds });
  }

  async verifyDirect(challenge: unknown, response: unknown, audience: string) {
    return this.post<{ result: string; holder_proof_of_possession: boolean }>(
      "/v1/direct/verify", { challenge, response, audience });
  }
}
