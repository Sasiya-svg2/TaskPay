const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Password",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    }
  });

async function telegramRequest(env, method, body) {
  if (!env.BOT_TOKEN) throw new Error("BOT_TOKEN is not configured");
  const response = await fetch(
    `https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }
  );
  const result = await response.json();
  if (!result.ok) throw new Error(result.description || "Telegram API error");
  return result;
}

async function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) return null;

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  if (!receivedHash) return null;
  params.delete("hash");

  const authDate = Number(params.get("auth_date"));
  if (!authDate || Date.now() / 1000 - authDate > 86400) return null;

  const checkString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const encoder = new TextEncoder();
  const secretKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode("WebAppData"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const secret = await crypto.subtle.sign(
    "HMAC",
    secretKey,
    encoder.encode(botToken)
  );

  const hmacKey = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    encoder.encode(checkString)
  );

  const actualHash = [...new Uint8Array(signature)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  if (actualHash.length !== receivedHash.length) return null;

  let mismatch = 0;
  for (let i = 0; i < actualHash.length; i++) {
    mismatch |= actualHash.charCodeAt(i) ^ receivedHash.charCodeAt(i);
  }
  if (mismatch !== 0) return null;

  try {
    return JSON.parse(params.get("user") || "null");
  } catch {
    return null;
  }
}

async function getUser(request, env) {
  const initData = request.headers.get("X-Telegram-Init-Data") || "";
  const user = await verifyTelegramInitData(initData, env.BOT_TOKEN);

  if (!user?.id) {
    return { error: json({ error: "Open this app from Telegram." }, 401) };
  }

  return { user };
}

function isAdmin(request, env) {
  const password = request.headers.get("X-Admin-Password") || "";
  return Boolean(env.ADMIN_PASSWORD && password === env.ADMIN_PASSWORD);
}

async function notifyAdmin(env, message, keyboard) {
  if (!env.ADMIN_TELEGRAM_ID) return;
  await telegramRequest(env, "sendMessage", {
    chat_id: env.ADMIN_TELEGRAM_ID,
    text: message,
    ...(keyboard ? { reply_markup: keyboard } : {})
  });
}

async function ensureUser(db, user, startParam) {
  const telegramId = String(user.id);
  let referral = null;

  if (startParam?.startsWith("ref_")) {
    const candidate = startParam.slice(4);
    if (candidate !== telegramId) {
      const exists = await db.prepare(
        "SELECT telegram_id FROM users WHERE telegram_id = ?"
      ).bind(candidate).first();
      if (exists) referral = candidate;
    }
  }

  await db.prepare(`
    INSERT OR IGNORE INTO users
      (telegram_id, username, first_name, referred_by)
    VALUES (?, ?, ?, ?)
  `).bind(
    telegramId,
    user.username || "",
    user.first_name || "",
    referral
  ).run();

  return telegramId;
}

async function handleApi(request, env, url) {
  const db = env.DB;
  const method = request.method;
  const path = url.pathname;

  if (method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type, X-Telegram-Init-Data, X-Admin-Password",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
      }
    });
  }

  if (path.startsWith("/api/admin/")) {
    if (!isAdmin(request, env)) {
      return json({ error: "Unauthorized" }, 401);
    }

    if (path === "/api/admin/overview" && method === "GET") {
      const users = await db.prepare(
        "SELECT COUNT(*) AS count FROM users"
      ).first();
      const tasks = await db.prepare(
        "SELECT COUNT(*) AS count FROM tasks WHERE active = 1"
      ).first();
      const withdrawals = await db.prepare(
        "SELECT COUNT(*) AS count FROM withdrawals WHERE status = 'pending'"
      ).first();
      const claims = await db.prepare(
        "SELECT COUNT(*) AS count FROM task_claims WHERE status = 'pending'"
      ).first();

      return json({
        users: users.count,
        tasks: tasks.count,
        pendingWithdrawals: withdrawals.count,
        pendingClaims: claims.count
      });
    }

    if (path === "/api/admin/tasks" && method === "GET") {
      const result = await db.prepare(
        "SELECT * FROM tasks ORDER BY id DESC"
      ).all();
      return json(result.results);
    }

    if (path === "/api/admin/tasks" && method === "POST") {
      const body = await request.json();
      const title = String(body.title || "").trim();
      const description = String(body.description || "").trim();
      const taskUrl = String(body.url || "").trim();
      const reward = Number(body.reward ?? 0.02);

      if (!title || !Number.isFinite(reward) || reward <= 0 || reward > 100) {
        return json({ error: "Enter a valid title and reward." }, 400);
      }

      await db.prepare(`
        INSERT INTO tasks (title, description, url, reward, active)
        VALUES (?, ?, ?, ?, 1)
      `).bind(title, description, taskUrl, reward).run();

      return json({ ok: true });
    }

    const taskMatch = path.match(/^\/api\/admin\/tasks\/(\d+)$/);
    if (taskMatch && method === "POST") {
      await db.prepare(
        "UPDATE tasks SET active = 0 WHERE id = ?"
      ).bind(Number(taskMatch[1])).run();
      return json({ ok: true });
    }

    if (path === "/api/admin/claims" && method === "GET") {
      const result = await db.prepare(`
        SELECT c.id, c.telegram_id, c.task_id, c.status, c.proof,
               c.created_at, t.title, t.reward
        FROM task_claims c
        JOIN tasks t ON t.id = c.task_id
        WHERE c.status = 'pending'
        ORDER BY c.id DESC
      `).all();
      return json(result.results);
    }

    const claimMatch = path.match(/^\/api\/admin\/claims\/(\d+)\/(approve|reject)$/);
    if (claimMatch && method === "POST") {
      const claimId = Number(claimMatch[1]);
      const action = claimMatch[2];

      const claim = await db.prepare(`
        SELECT c.*, t.reward, t.title
        FROM task_claims c JOIN tasks t ON t.id = c.task_id
        WHERE c.id = ? AND c.status = 'pending'
      `).bind(claimId).first();

      if (!claim) return json({ error: "Claim not found or already reviewed." }, 404);

      if (action === "approve") {
        const batch = [
          db.prepare(`
            UPDATE task_claims SET status = 'approved'
            WHERE id = ? AND status = 'pending'
          `).bind(claimId),
          db.prepare(`
            UPDATE users SET balance = balance + ?,
              total_earned = total_earned + ?
            WHERE telegram_id = ?
              AND EXISTS (
                SELECT 1 FROM task_claims
                WHERE id = ? AND status = 'pending'
              )
          `).bind(claim.reward, claim.reward, claim.telegram_id, claimId),
          db.prepare(`
            INSERT INTO ledger (telegram_id, amount, kind, reference)
            SELECT ?, ?, 'task_reward', ?
            WHERE EXISTS (
              SELECT 1 FROM task_claims
              WHERE id = ? AND status = 'pending'
            )
          `).bind(claim.telegram_id, claim.reward, String(claimId), claimId)
        ];
        await db.batch(batch);
        return json({ ok: true });
      }

      await db.prepare(
        "UPDATE task_claims SET status = 'rejected' WHERE id = ? AND status = 'pending'"
      ).bind(claimId).run();
      return json({ ok: true });
    }

    if (path === "/api/admin/withdrawals" && method === "GET") {
      const result = await db.prepare(`
        SELECT * FROM withdrawals ORDER BY
          CASE status WHEN 'pending' THEN 0 ELSE 1 END, id DESC
      `).all();
      return json(result.results);
    }

    const withdrawalMatch = path.match(
      /^\/api\/admin\/withdrawals\/(\d+)\/(approve|reject)$/
    );
    if (withdrawalMatch && method === "POST") {
      const withdrawalId = Number(withdrawalMatch[1]);
      const action = withdrawalMatch[2];
      const withdrawal = await db.prepare(
        "SELECT * FROM withdrawals WHERE id = ? AND status = 'pending'"
      ).bind(withdrawalId).first();

      if (!withdrawal) {
        return json({ error: "Withdrawal not found or already reviewed." }, 404);
      }

      if (action === "approve") {
        if (!env.PROOF_CHANNEL_ID) {
          return json({ error: "PROOF_CHANNEL_ID is not configured." }, 500);
        }

        await telegramRequest(env, "sendMessage", {
          chat_id: env.PROOF_CHANNEL_ID,
          text:
            "✅ Payment Approved\n" +
            `Request: #${withdrawal.id}\n` +
            `User ID: ${withdrawal.telegram_id}\n` +
            `Amount: $${Number(withdrawal.amount).toFixed(3)}\n` +
            `Binance ID: ${withdrawal.binance_id}\n` +
            "Status: Approved by admin"
        });

        await db.prepare(
          "UPDATE withdrawals SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'"
        ).bind(withdrawalId).run();
      } else {
        await db.prepare(
          "UPDATE withdrawals SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'"
        ).bind(withdrawalId).run();

        await db.prepare(
          "UPDATE users SET balance = balance + ? WHERE telegram_id = ?"
        ).bind(withdrawal.amount, withdrawal.telegram_id).run();
      }

      return json({ ok: true });
    }

    if (path === "/api/admin/users" && method === "GET") {
      const result = await db.prepare(`
        SELECT telegram_id, username, first_name, balance, total_earned,
               referred_by, created_at
        FROM users ORDER BY created_at DESC LIMIT 500
      `).all();
      return json(result.results);
    }

    return json({ error: "Admin route not found." }, 404);
  }

  const auth = await getUser(request, env);
  if (auth.error) return auth.error;
  const telegramUser = auth.user;
  const startParam = url.searchParams.get("startapp") || "";
  const telegramId = await ensureUser(db, telegramUser, startParam);

  if (path === "/api/me" && method === "GET") {
    const user = await db.prepare(`
      SELECT telegram_id, username, first_name, balance, total_earned,
             created_at, last_daily_claim
      FROM users WHERE telegram_id = ?
    `).bind(telegramId).first();

    const referrals = await db.prepare(
      "SELECT COUNT(*) AS count FROM users WHERE referred_by = ?"
    ).bind(telegramId).first();

    return json({ ...user, referrals: referrals.count });
  }

  if (path === "/api/tasks" && method === "GET") {
    const result = await db.prepare(`
      SELECT t.id, t.title, t.description, t.url, t.reward,
        (SELECT status FROM task_claims c
         WHERE c.task_id = t.id AND c.telegram_id = ?) AS claim_status
      FROM tasks t WHERE t.active = 1 ORDER BY t.id DESC
    `).bind(telegramId).all();

    return json(result.results);
  }

  if (path === "/api/daily-claim" && method === "POST") {
    const today = new Date().toISOString().slice(0, 10);
    const user = await db.prepare(
      "SELECT last_daily_claim FROM users WHERE telegram_id = ?"
    ).bind(telegramId).first();

    if (user.last_daily_claim === today) {
      return json({ error: "Daily reward already claimed today." }, 409);
    }

    const result = await db.prepare(`
      UPDATE users
      SET balance = balance + 0.015,
          total_earned = total_earned + 0.015,
          last_daily_claim = ?
      WHERE telegram_id = ?
        AND (last_daily_claim IS NULL OR last_daily_claim < ?)
    `).bind(today, telegramId, today).run();

    if (!result.meta.changes) {
      return json({ error: "Daily reward already claimed today." }, 409);
    }

    await db.prepare(
      "INSERT INTO ledger (telegram_id, amount, kind) VALUES (?, 0.015, 'daily_claim')"
    ).bind(telegramId).run();

    return json({ ok: true, reward: 0.015 });
  }

  if (path === "/api/task-claim" && method === "POST") {
    const body = await request.json();
    const taskId = Number(body.taskId);
    const proof = String(body.proof || "").trim();

    if (!Number.isInteger(taskId) || taskId < 1) {
      return json({ error: "Invalid task." }, 400);
    }

    const task = await db.prepare(
      "SELECT id FROM tasks WHERE id = ? AND active = 1"
    ).bind(taskId).first();

    if (!task) return json({ error: "Task is unavailable." }, 404);

    try {
      await db.prepare(`
        INSERT INTO task_claims (telegram_id, task_id, proof)
        VALUES (?, ?, ?)
      `).bind(telegramId, taskId, proof).run();
    } catch {
      return json({ error: "You have already submitted this task." }, 409);
    }

    await notifyAdmin(
      env,
      "📝 New Task Submission\n" +
      `User ID: ${telegramId}\nTask ID: ${taskId}\n` +
      `Proof: ${proof || "Not provided"}\n\n` +
      "Review this submission in the TaskPay Admin Panel."
    );

    return json({ ok: true, status: "pending" });
  }

  if (path === "/api/withdraw" && method === "POST") {
    const body = await request.json();
    const amount = Number(body.amount);
    const binanceId = String(body.binanceId || "").trim();

    if (!Number.isFinite(amount) || amount < 5 || amount > 100000) {
      return json({ error: "Minimum withdrawal is $5.00." }, 400);
    }

    if (binanceId.length < 2 || binanceId.length > 100) {
      return json({ error: "Enter a valid Binance ID." }, 400);
    }

    const pending = await db.prepare(
      "SELECT id FROM withdrawals WHERE telegram_id = ? AND status = 'pending'"
    ).bind(telegramId).first();

    if (pending) {
      return json({ error: "You already have a pending withdrawal." }, 409);
    }

    const result = await db.prepare(`
      UPDATE users SET balance = balance - ?
      WHERE telegram_id = ? AND balance >= ?
    `).bind(amount, telegramId, amount).run();

    if (!result.meta.changes) {
      return json({ error: "Insufficient balance." }, 400);
    }

    const inserted = await db.prepare(`
      INSERT INTO withdrawals (telegram_id, amount, binance_id)
      VALUES (?, ?, ?)
    `).bind(telegramId, amount, binanceId).run();

    const withdrawalId = inserted.meta.last_row_id;

    try {
      await notifyAdmin(
        env,
        "💸 New Withdrawal Request\n" +
        `Request: #${withdrawalId}\nUser ID: ${telegramId}\n` +
        `Amount: $${amount.toFixed(3)}\nBinance ID: ${binanceId}\n\n` +
        "Review in the TaskPay Admin Panel."
      );
    } catch (error) {
      console.error("Admin notification failed", error);
    }

    return json({ ok: true, status: "pending", withdrawalId });
  }

  return json({ error: "API route not found." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (error) {
        console.error(error);
        return json({ error: "Server error. Check Worker logs." }, 500);
      }
    }

    if (url.pathname === "/health") {
      return json({ ok: true, app: "TaskPay" });
    }

    return env.ASSETS.fetch(request);
  }
};
