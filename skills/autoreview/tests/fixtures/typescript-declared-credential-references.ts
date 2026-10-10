type SecretRef = { source: "env"; id: string };
type CredentialUnavailableDiagnostic = { path: string; reason: string };

declare const tokenRef: SecretRef;
declare const keyRef: SecretRef;
declare const inlinePassword: string;
declare const inlineSecret: string;
declare const accountFileToken: string;
declare const baseFileToken: string;
declare const passwordResolution: { password: string };
declare const secretResolution: { secret: string };
declare const tokenResolution: { token: string };
declare const accountTokenFile: { token: string };
declare const channelTokenFile: { token: string };
declare const merged: { apiPassword: string; passwordFile: string };
declare const tryReadSecretFileSync: (...args: unknown[]) => string;
declare const normalizeResolvedSecretInputString: (options: unknown) => string;
declare const resolveToken: (options: unknown) => { value: string };

// These external values establish references without embedding credential bytes.
declare const fileReadResult: { password: string };
const filePassword = fileReadResult.password;
const configPassword = merged.apiPassword;
const token = { value: tokenResolution.token };
const priorPasswordFileError = /IRC password file.*must not be a symlink/;

export type CredentialPlumbing = {
  tokenRef?: SecretRef;
  keyRef?: SecretRef;
  credentialDiagnostics?: CredentialUnavailableDiagnostic[];
};

export const resolvedCredentialPlumbing = {
  token: tokenRef,
  apiKey: keyRef,
  password: filePassword,
  configPassword,
  nextPassword: inlinePassword,
  secret: inlineSecret,
  accountToken: accountFileToken,
  baseToken: baseFileToken,
  resolvedPassword: passwordResolution.password,
  resolvedSecret: secretResolution.secret,
  resolvedToken: tokenResolution.token,
  accountTokenFile: accountTokenFile.token,
  channelTokenFile: channelTokenFile.token,
  apiPassword: merged.apiPassword,
  channelAccessToken: token.value,
};
