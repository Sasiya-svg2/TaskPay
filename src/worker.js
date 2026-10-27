
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, X-Telegram-Init-Data, X-Admin-Password",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
});

async function telegramRequest(env, method, body) {
  if (!env.BOT_TOKEN) throw new Error("BOT_TOKEN is not configured");
  const response = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok || !result.ok) throw new Error(result.description || "Telegram API error");
  return result.result;
}

async function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) return null;

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");
  if (!receivedHash) return null;
  params.delete("hash");

  const authDate = Number(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);
  if (!authDate || authDate > now + 60 || now - authDate > 86400) return null;

  const checkString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const encoder = new TextEncoder();
  const tokenKey = await crypto.subtle.importKey(
    "raw", encoder.encode(botToken), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const secret = await crypto.subtle.sign("HMAC", tokenKey, encoder.encode("WebAppData"));

  const hmacKey = await crypto.subtle.importKey(
    "raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", hmacKey, encoder.encode(checkString));
  const actualHash = [...new Uint8Array(signature)]
    .map(b => b.toString(16).padStart(2, "0")).join("");

  if (actualHash.length !== receivedHash.length) return null;
  let mismatch = 0;
  for (let i = 0; i < actualHash.length; i++) {
    mismatch |= actualHash.charCodeAt(i) ^ receivedHash.charCodeAt(i);
  }
  if (mismatch !== 0) return null;

  try {
    return {
      user: JSON.parse(params.get("user") || "null"),
      startParam: params.get("start_param") || ""
    };
  } catch {
    return null;
  }
}

async function getAuth(request, env) {
  const initData = request.headers.get("X-Telegram-Init-Data") || "";
  const verified = await verifyTelegramInitData(initData, env.BOT_TOKEN);
  if (!verified?.user?.id) return { error: json({ error: "Open this app from Telegram." }, 401) };
  return verified;
}

function isAdmin(request, env) {
  return Boolean(env.ADMIN_PASSWORD) &&
    request.headers.get("X-Admin-Password") === env.ADMIN_PASSWORD;
}

async function notifyAdmin(env, message) {
  if (!env.ADMIN_TELEGRAM_ID) return;
  await telegramRequest(env, "sendMessage", {
    chat_id: env.ADMIN_TELEGRAM_ID,
    text: message
  });
}

async function ensureUser(db, user, startParam) {
  const id = String(user.id);
  const existing = await db.prepare(
    "SELECT telegram_id FROM users WHERE telegram_id = ?"
  ).bind(id).first();

  if (existing) {
    await db.prepare("UPDATE users SET username = ?, first_name = ? WHERE telegram_id = ?")
      .bind(user.username || "", user.first_name || "", id).run();
    return id;
  }

  let referrer = "";
  if (startParam.startsWith("ref_")) {
    const candidate = startParam.slice(4);
    if (candidate !== id) {
      const found = await db.prepare(
        "SELECT telegram_id FROM users WHERE telegram_id = ?"
      ).bind(candidate).first();
      if (found) referrer = candidate;
    }
  }

  await db.prepare(`
    INSERT INTO users (telegram_id, username, first_name, referred_by)
    VALUES (?, ?, ?, ?)
  `).bind(id, user.username || "", user.first_name || "", referrer || null).run();

  if (referrer) {
    const reward = 0.01;
    await db.batch([
      db.prepare("UPDATE users SET balance = balance + ?, total_earned = total_earned + ? WHERE telegram_id = ?")
        .bind(reward, reward, referrer),
      db.prepare("INSERT INTO ledger (telegram_id, amount, kind, reference) VALUES (?, ?, 'referral_reward', ?)")
        .bind(referrer, reward, id)
    ]);
    try {
      await telegramRequest(env, "sendMessage", {
        chat_id: referrer,
        text: `🎉 A new friend joined using your link. Referral reward: $${reward.toFixed(3)}`
      });
    } catch {}
  }

  return id;
}

async function isMember(env, chatId, userId) {
  if (!chatId) return false;
  const member = await telegramRequest(env, "getChatMember", {
    chat_id: chatId,
    user_id: Number(userId)
  });
  return ["creator", "administrator", "member"].includes(member.status) ||
    (member.status === "restricted" && member.is_member === true);
}

async function handleApi(request, env, url) {
  const db = env.DB;
  const { pathname: path } = url;
  const method = request.method;

  if (method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  if (path.startsWith("/api/admin/")) {
    if (!isAdmin(request, env)) return json({ error: "Unauthorized" }, 401);

    if (path === "/api/admin/overview" && method === "GET") {
      const [users, tasks, claims, withdrawals, requests] = await Promise.all([
        db.prepare("SELECT COUNT(*) count FROM users").first(),
        db.prepare("SELECT COUNT(*) count FROM tasks WHERE active = 1").first(),
        db.prepare("SELECT COUNT(*) count FROM task_claims WHERE status = 'pending'").first(),
        db.prepare("SELECT COUNT(*) count FROM withdrawals WHERE status = 'pending'").first(),
        db.prepare("SELECT COUNT(*) count FROM task_requests WHERE status IN ('awaiting_payment','pending_review')").first()
      ]);
      return json({
        users: users.count, tasks: tasks.count, pendingClaims: claims.count,
        pendingWithdrawals: withdrawals.count, pendingTaskRequests: requests.count
      });
    }

    if (path === "/api/admin/tasks" && method === "GET") {
      return json((await db.prepare("SELECT * FROM tasks ORDER BY id DESC").all()).results);
    }

    if (path === "/api/admin/tasks" && method === "POST") {
      const b = await request.json();
      const title = String(b.title || "").trim();
      const description = String(b.description || "").trim();
      const taskUrl = String(b.url || "").trim();
      const reward = Number(b.reward ?? 0.02);
      const taskType = ["link", "channel", "group"].includes(b.task_type) ? b.task_type : "link";
      const chatId = String(b.chat_id || "").trim();

      if (!title || !Number.isFinite(reward) || reward <= 0 || reward > 100) {
        return json({ error: "Enter a valid title and reward." }, 400);
      }
      if (taskType !== "link" && !chatId) {
        return json({ error: "Enter the Telegram channel/group username or chat ID." }, 400);
      }

      await db.prepare(`
        INSERT INTO tasks (title, description, url, reward, active, task_type, chat_id)
        VALUES (?, ?, ?, ?, 1, ?, ?)
      `).bind(title, description, taskUrl, reward, taskType, chatId).run();
      return json({ ok: true });
    }

    const removeTask = path.match(/^\/api\/admin\/tasks\/(\d+)$/);
    if (removeTask && method === "POST") {
      await db.prepare("UPDATE tasks SET active = 0 WHERE id = ?").bind(Number(removeTask[1])).run();
      return json({ ok: true });
    }

    if (path === "/api/admin/claims" && method === "GET") {
      return json((await db.prepare(`
        SELECT c.id, c.telegram_id, c.task_id, c.status, c.proof, c.created_at,
               t.title, t.reward
        FROM task_claims c JOIN tasks t ON t.id = c.task_id
        WHERE c.status = 'pending' ORDER BY c.id DESC
      `).all()).results);
    }

    const reviewClaim = path.match(/^\/api\/admin\/claims\/(\d+)\/(approve|reject)$/);
    if (reviewClaim && method === "POST") {
      const id = Number(reviewClaim[1]);
      const action = reviewClaim[2];
      const claim = await db.prepare(`
        SELECT c.*, t.reward FROM task_claims c
        JOIN tasks t ON t.id = c.task_id
        WHERE c.id = ? AND c.status = 'pending'
      `).bind(id).first();
      if (!claim) return json({ error: "Claim not found or already reviewed." }, 404);

      if (action === "approve") {
        const result = await db.prepare(
          "UPDATE task_claims SET status = 'approved' WHERE id = ? AND status = 'pending'"
        ).bind(id).run();
        if (!result.meta.changes) return json({ error: "Already reviewed." }, 409);
        await db.batch([
          db.prepare("UPDATE users SET balance = balance + ?, total_earned = total_earned + ? WHERE telegram_id = ?")
            .bind(claim.reward, claim.reward, claim.telegram_id),
          db.prepare("INSERT INTO ledger (telegram_id, amount, kind, reference) VALUES (?, ?, 'task_reward', ?)")
            .bind(claim.telegram_id, claim.reward, String(id))
        ]);
      } else {
        await db.prepare("UPDATE task_claims SET status = 'rejected' WHERE id = ? AND status = 'pending'")
          .bind(id).run();
      }
      return json({ ok: true });
    }

    if (path === "/api/admin/task-requests" && method === "GET") {
      return json((await db.prepare("SELECT * FROM task_requests ORDER BY id DESC").all()).results);
    }

    const reviewRequest = path.match(/^\/api\/admin\/task-requests\/(\d+)\/(approve|reject)$/);
    if (reviewRequest && method === "POST") {
      const id = Number(reviewRequest[1]);
      const action = reviewRequest[2];
      const req = await db.prepare(
        "SELECT * FROM task_requests WHERE id = ? AND status = 'pending_review'"
      ).bind(id).first();
      if (!req) return json({ error: "Request not found or payment not submitted." }, 404);

      if (action === "approve") {
        const taskUrl = req.target_url;
        const usernameMatch = taskUrl.match(/t\.me\/([A-Za-z0-9_]+)/i);
        const chatId = usernameMatch ? "@" + usernameMatch[1] : "";
        const taskType = chatId ? "channel" : "link";

        await db.batch([
          db.prepare(`
            INSERT INTO tasks (title, description, url, reward, active, task_type, chat_id)
            VALUES (?, ?, ?, 0.02, 1, ?, ?)
          `).bind(req.title, req.description, taskUrl, taskType, chatId),
          db.prepare("UPDATE task_requests SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending_review'")
            .bind(id)
        ]);
        try {
          await telegramRequest(env, "sendMessage", {
            chat_id: req.telegram_id,
            text: `✅ Your task request #${id} was approved and added to TaskPay.`
          });
        } catch {}
      } else {
        await db.prepare("UPDATE task_requests SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP WHERE id = ?")
          .bind(id).run();
        try {
          await telegramRequest(env, "sendMessage", {
            chat_id: req.telegram_id,
            text: `❌ Your task request #${id} was rejected. Contact Help Center for details.`
          });
        } catch {}
      }
      return json({ ok: true });
    }

    if (path === "/api/admin/withdrawals" && method === "GET") {
      return json((await db.prepare("SELECT * FROM withdrawals ORDER BY id DESC").all()).results);
    }

    const reviewWithdrawal = path.match(/^\/api\/admin\/withdrawals\/(\d+)\/(approve|reject)$/);
    if (reviewWithdrawal && method === "POST") {
      const id = Number(reviewWithdrawal[1]);
      const action = reviewWithdrawal[2];
      const w = await db.prepare("SELECT * FROM withdrawals WHERE id = ? AND status = 'pending'").bind(id).first();
      if (!w) return json({ error: "Withdrawal not found or already reviewed." }, 404);

      if (action === "approve") {
        await db.prepare("UPDATE withdrawals SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'")
          .bind(id).run();
        if (env.PROOF_CHANNEL_ID) {
          try {
            await telegramRequest(env, "sendMessage", {
              chat_id: env.PROOF_CHANNEL_ID,
              text: `✅ Withdrawal approved\nRequest: #${id}\nUser ID: ${w.telegram_id}\nAmount: $${Number(w.amount).toFixed(3)}\nBinance ID: ${w.binance_id}`
            });
          } catch {}
        }
      } else {
        const result = await db.prepare("UPDATE withdrawals SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'")
          .bind(id).run();
        if (result.meta.changes) {
          await db.prepare("UPDATE users SET balance = balance + ? WHERE telegram_id = ?")
            .bind(w.amount, w.telegram_id).run();
        }
      }
      return json({ ok: true });
    }

    if (path === "/api/admin/users" && method === "GET") {
      return json((await db.prepare(`
        SELECT telegram_id, username, first_name, balance, total_earned, referred_by, created_at
        FROM users ORDER BY created_at DESC LIMIT 500
      `).all()).results);
    }

    return json({ error: "Admin route not found." }, 404);
  }

  const auth = await getAuth(request, env);
  if (auth.error) return auth.error;
  const user = auth.user;
  const telegramId = await ensureUser(db, user, auth.startParam);

  if (path === "/api/config" && method === "GET") {
    return json({
      botUsername: env.BOT_USERNAME || "task_v1_bot",
      officialChannel: "https://t.me/flash_bot_update",
      usdtAddress: env.USDT_BEP20_ADDRESS || ""
    });
  }

  if (path === "/api/me" && method === "GET") {
    const me = await db.prepare(`
      SELECT telegram_id, username, first_name, balance, total_earned, created_at, last_daily_claim
      FROM users WHERE telegram_id = ?
    `).bind(telegramId).first();
    const referrals = await db.prepare("SELECT COUNT(*) count FROM users WHERE referred_by = ?")
      .bind(telegramId).first();
    return json({ ...me, referrals: referrals.count });
  }

  if (path === "/api/tasks" && method === "GET") {
    return json((await db.prepare(`
      SELECT t.id, t.title, t.description, t.url, t.reward, t.task_type, t.chat_id,
        (SELECT status FROM task_claims c WHERE c.task_id = t.id AND c.telegram_id = ?) claim_status
      FROM tasks t WHERE t.active = 1 ORDER BY t.id DESC
    `).bind(telegramId).all()).results);
  }

  if (path === "/api/task-claim" && method === "POST") {
    const body = await request.json();
    const taskId = Number(body.taskId);
    if (!Number.isInteger(taskId) || taskId < 1) return json({ error: "Invalid task." }, 400);

    const task = await db.prepare("SELECT * FROM tasks WHERE id = ? AND active = 1")
      .bind(taskId).first();
    if (!task) return json({ error: "Task is unavailable." }, 404);

    if (!["channel", "group"].includes(task.task_type) || !task.chat_id) {
      const proof = String(body.proof || "").trim();
      try {
        await db.prepare("INSERT INTO task_claims (telegram_id, task_id, proof) VALUES (?, ?, ?)")
          .bind(telegramId, taskId, proof).run();
      } catch {
        return json({ error: "You have already submitted this task." }, 409);
      }
      try {
        await notifyAdmin(env, `📝 Task submission\nUser ID: ${telegramId}\nTask: ${task.title}\nProof: ${proof || "Not provided"}\nReview in TaskPay Admin Panel.`);
      } catch {}
      return json({ ok: true, status: "pending" });
    }

    let member = false;
    try {
      member = await isMember(env, task.chat_id, telegramId);
    } catch {
      return json({ error: "Could not verify membership. Please check that the bot is an admin in the channel/group." }, 400);
    }
    if (!member) return json({ error: "Join the channel/group first, then try again." }, 400);

    try {
      const inserted = await db.prepare(`
        INSERT INTO task_claims (telegram_id, task_id, status, proof)
        VALUES (?, ?, 'approved', 'Telegram membership verified')
      `).bind(telegramId, taskId).run();
      if (!inserted.meta.changes) return json({ error: "Task already completed." }, 409);
    } catch {
      return json({ error: "Task already completed." }, 409);
    }

    await db.batch([
      db.prepare("UPDATE users SET balance = balance + ?, total_earned = total_earned + ? WHERE telegram_id = ?")
        .bind(task.reward, task.reward, telegramId),
      db.prepare("INSERT INTO ledger (telegram_id, amount, kind, reference) VALUES (?, ?, 'task_reward', ?)")
        .bind(telegramId, task.reward, String(taskId))
    ]);
    return json({ ok: true, status: "approved", reward: task.reward });
  }

  if (path === "/api/daily-claim" && method === "POST") {
    const today = new Date().toISOString().slice(0, 10);
    const result = await db.prepare(`
      UPDATE users SET balance = balance + 0.015, total_earned = total_earned + 0.015, last_daily_claim = ?
      WHERE telegram_id = ? AND (last_daily_claim IS NULL OR last_daily_claim < ?)
    `).bind(today, telegramId, today).run();
    if (!result.meta.changes) return json({ error: "Daily reward already claimed today." }, 409);
    await db.prepare("INSERT INTO ledger (telegram_id, amount, kind) VALUES (?, 0.015, 'daily_claim')")
      .bind(telegramId).run();
    return json({ ok: true, reward: 0.015 });
  }

  if (path === "/api/task-requests" && method === "POST") {
    const body = await request.json();
    const title = String(body.title || "").trim();
    const description = String(body.description || "").trim();
    const targetUrl = String(body.targetUrl || "").trim();
    const memberCount = Math.max(0, Math.floor(Number(body.memberCount || 0)));
    const taxId = String(body.taxId || "").trim();
    const paymentTxId = String(body.paymentTxId || "").trim();
    const price = memberCount > 2000 ? 6 : 4;

    if (title.length < 3 || title.length > 120) return json({ error: "Task title must be 3–120 characters." }, 400);
    if (!/^https:\/\/t\.me\/[A-Za-z0-9_+/-]+/i.test(targetUrl)) return json({ error: "Enter a valid Telegram link." }, 400);
    if (!taxId || taxId.length > 100) return json({ error: "Enter your Tax ID." }, 400);
    if (!paymentTxId || paymentTxId.length < 8 || paymentTxId.length > 200) {
      return json({ error: "Enter the USDT BEP20 transaction hash after payment." }, 400);
    }

    const address = String(env.USDT_BEP20_ADDRESS || "").trim();
    if (!address) return json({ error: "USDT payment address is not configured yet. Please contact Help Center." }, 400);

    const result = await db.prepare(`
      INSERT INTO task_requests
        (telegram_id, title, description, target_url, member_count, price_usd, tax_id, payment_txid, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_review')
    `).bind(telegramId, title, description, targetUrl, memberCount, price, taxId, paymentTxId).run();

    try {
      await notifyAdmin(env, `💳 New Task Request #${result.meta.last_row_id}\nUser ID: ${telegramId}\nTitle: ${title}\nTarget: ${targetUrl}\nMembers: ${memberCount}\nPrice: $${price}\nTax ID: ${taxId}\nTXID: ${paymentTxId}\nReview in Admin Panel.`);
    } catch {}
    return json({ ok: true, requestId: result.meta.last_row_id, status: "pending_review" });
  }

  if (path === "/api/help" && method === "POST") {
    const body = await request.json();
    const message = String(body.message || "").trim();
    if (message.length < 2 || message.length > 2000) {
      return json({ error: "Message must be 2–2000 characters." }, 400);
    }
    await db.prepare(`
      INSERT INTO help_messages (telegram_id, username, first_name, message)
      VALUES (?, ?, ?, ?)
    `).bind(telegramId, user.username || "", user.first_name || "", message).run();

    await notifyAdmin(env,
      `📩 TaskPay Help Center\nName: ${user.first_name || "User"}\nUsername: ${user.username ? "@" + user.username : "Not set"}\nTelegram ID: ${telegramId}\n\nMessage:\n${message}`
    );
    return json({ ok: true });
  }

  if (path === "/api/withdraw" && method === "POST") {
    const body = await request.json();
    const amount = Number(body.amount);
    const binanceId = String(body.binanceId || "").trim();
    if (!Number.isFinite(amount) || amount < 5 || amount > 100000) {
      return json({ error: "Minimum withdrawal is $5.00." }, 400);
    }
    if (binanceId.length < 2 || binanceId.length > 100) return json({ error: "Enter a valid Binance ID." }, 400);

    const pending = await db.prepare("SELECT id FROM withdrawals WHERE telegram_id = ? AND status = 'pending'")
      .bind(telegramId).first();
    if (pending) return json({ error: "You already have a pending withdrawal." }, 409);

    const debit = await db.prepare("UPDATE users SET balance = balance - ? WHERE telegram_id = ? AND balance >= ?")
      .bind(amount, telegramId, amount).run();
    if (!debit.meta.changes) return json({ error: "Insufficient balance." }, 400);

    const inserted = await db.prepare("INSERT INTO withdrawals (telegram_id, amount, binance_id) VALUES (?, ?, ?)")
      .bind(telegramId, amount, binanceId).run();
    try {
      await notifyAdmin(env, `💸 Withdrawal Request #${inserted.meta.last_row_id}\nUser ID: ${telegramId}\nAmount: $${amount.toFixed(3)}\nBinance ID: ${binanceId}`);
    } catch {}
    return json({ ok: true, status: "pending", withdrawalId: inserted.meta.last_row_id });
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
    if (url.pathname === "/health") return json({ ok: true, app: "TaskPay" });
    return env.ASSETS.fetch(request);
  }
};
