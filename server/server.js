const { createClient } = require("@supabase/supabase-js");
const { createApp } = require("./createApp");
require("dotenv").config();

const port = process.env.PORT || 3000;
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error("CRITICAL: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in environment variables.");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false
  }
});

const config = {
  chainId: process.env.CHAIN_ID ? Number(process.env.CHAIN_ID) : undefined,
  roundId: process.env.ROUND_ID,
  proxyAddress: process.env.PROXY_ADDRESS,
  contractAddress: process.env.CONTRACT_ADDRESS,
  trustedCredentialIssuer: process.env.TRUSTED_CREDENTIAL_ISSUER,
  credentialPepper: process.env.CREDENTIAL_PEPPER,
  testMode: process.env.TEST_MODE === "true"
};

let app;
try {
  app = createApp(supabase, config);
} catch (err) {
  console.error("CRITICAL: Database Proxy startup failed due to configuration breach.");
  console.error(err.message);
  process.exit(1);
}

app.listen(port, () => {
  console.log(`Pharmacy Fiduciary Commons database proxy listening on port ${port}`);
});
