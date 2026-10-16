import process from "node:process";

const accountConfig = { token: process.env.FIXTURE_ACCOUNT_TOKEN };
const merged = { token: process.env.FIXTURE_CONFIG_TOKEN };

// This synthetic resolver returns its input value. Both callers retain their
// own producer objects so no unbound receiver can establish credential origin.
function resolveRuntimeTokenValue(options: { value: string | undefined }): string | undefined {
  return options.value;
}

function resolveAccountToken() {
  const accountToken = resolveRuntimeTokenValue({
    value: accountConfig.token,
  });
  return accountToken;
}

function resolveConfigToken() {
  const configToken = resolveRuntimeTokenValue({
    value: merged.token,
  });
  return configToken;
}
