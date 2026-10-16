import process from "node:process";
declare const accountId: string;
declare const filePath: string;
const secretRef = process.env.FIXTURE_SECRET_REF;
declare const tryReadSecretFileSync: (...args: unknown[]) => string;
// This synthetic normalizer returns only the input value.
// The diagnostic path is not a credential result.
function normalizeResolvedSecretInputString(options: { value: string | undefined; path: string }): string | undefined {
  return options.value;
}

export const passwordFile = tryReadSecretFileSync(filePath, "IRC password file", {
  credentialDiagnostic: {
    configPath: `channels.irc.accounts.${accountId}.passwordFile`,
  },
});
export const nickservFile = tryReadSecretFileSync(filePath, "IRC NickServ password file", {
  credentialDiagnostic: {
    configPath: `channels.irc.accounts.${accountId}.nickserv.passwordFile`,
  },
});
const params = {
  value: secretRef,
  path: `channels.nextcloud-talk.accounts.${accountId}.botSecret`,
};
export const botSecret = normalizeResolvedSecretInputString(params);
export const botSecretFile = tryReadSecretFileSync(filePath, "Nextcloud bot secret file", {
  credentialDiagnostic: {
    configPath: `channels.nextcloud-talk.accounts.${accountId}.botSecretFile`,
  },
});
export const tokenFile = tryReadSecretFileSync(
  filePath,
  `channels.telegram.accounts.${accountId}.tokenFile`,
  { rejectSymlink: true },
);
