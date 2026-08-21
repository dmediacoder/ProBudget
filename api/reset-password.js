// Vercel serverless function: POST /api/reset-password
// Body: { email: string, newPassword: string }
// Directly sets a new password for the account with that email — no email
// confirmation link. Uses the Supabase SERVICE ROLE key, which must be set
// as an environment variable in your Vercel project (never in client code).

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, newPassword } = req.body || {};

  if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ error: 'A valid email is required' });
  }
  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8 || !/\d/.test(newPassword)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters and include a number' });
  }

  const SB_URL = process.env.SUPABASE_URL;
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!SB_URL || !SERVICE_KEY) {
    return res.status(500).json({ error: 'Server is not configured (missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY)' });
  }

  try {
    // 1. Look up the user by email — search the admin user list directly
    //    rather than relying on the ?email= query filter, since not all
    //    Supabase project versions support server-side email filtering on
    //    this endpoint (some silently ignore it and return all users).
    const targetEmail = email.trim().toLowerCase();
    let user = null;
    let page = 1;
    const perPage = 1000;

    while (!user) {
      const lookupRes = await fetch(
        `${SB_URL}/auth/v1/admin/users?page=${page}&per_page=${perPage}`,
        { headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}` } }
      );
      if (!lookupRes.ok) {
        const errText = await lookupRes.text();
        return res.status(500).json({ error: 'Could not look up account: ' + errText });
      }
      const lookupData = await lookupRes.json();
      const pageUsers = Array.isArray(lookupData) ? lookupData : (lookupData.users || []);

      user = pageUsers.find(u => (u.email || '').toLowerCase() === targetEmail) || null;

      if (user || pageUsers.length < perPage) break; // found it, or no more pages
      page++;
      if (page > 20) break; // safety cap (20,000 users) to avoid an infinite loop
    }

    if (!user || !user.id) {
      // Same generic response whether or not the account exists, to avoid
      // leaking which emails are registered.
      return res.status(200).json({ success: true });
    }

    // 2. Directly set the new password
    const updateRes = await fetch(`${SB_URL}/auth/v1/admin/users/${user.id}`, {
      method: 'PUT',
      headers: {
        apikey: SERVICE_KEY,
        Authorization: `Bearer ${SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ password: newPassword }),
    });

    if (!updateRes.ok) {
      const err = await updateRes.json().catch(() => ({}));
      return res.status(400).json({ error: err.msg || err.message || 'Could not update password' });
    }

    return res.status(200).json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: 'Unexpected error: ' + e.message });
  }
}
