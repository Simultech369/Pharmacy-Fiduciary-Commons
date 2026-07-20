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

const app = createApp(supabase);

app.listen(port, () => {
  console.log(`Pharmacy Fiduciary Commons database proxy listening on port ${port}`);
});
