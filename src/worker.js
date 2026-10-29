const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Content-Type, X-Telegram-Init-Data, X-Admin-Password",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8"
    }
  });

async function telegramRequest(env, method, body) {
  if (!env.BOT_TOKEN) {
    throw new Error("BOT_TOKEN is not configured");
  }

  const response = await fetch(
    `https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }
  );

  const result = await response.json();

  if (!response.ok || !result.ok) {
    throw new Error(result.description || "Telegram API error");
  }

  return result.result;
}

// Verify Telegram Mini App initData using Telegram's HMAC-SHA-256 method.
async function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) return null;

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
      return null;
    }

    params.delete("hash");

    const authDate = Number(params.get("auth_date"));
    const now = Math.floor(Date.now() / 1000);

    if (
      !Number.isFinite(authDate) ||
      !authDate ||
      authDate > now + 60 ||
      now - authDate > 86400
    ) {
      return null;
    }

    const checkString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const encoder = new TextEncoder();

    // Telegram secret key = HMAC-SHA-256("WebAppData", botToken).
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
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    if (actualHash.length !== receivedHash.length) {
      return null;
    }

    let mismatch = 0;

    for (let i = 0; i < actualHash.length; i++) {
      mismatch |=
        actualHash.charCodeAt(i) ^ receivedHash.charCodeAt(i);
    }

    if (mismatch !== 0) return null;

    const user = JSON.parse(params.get("user") || "null");

    if (!user?.id) return null;

    return {
      user,
      startParam: params.get("start_param") || ""
    };
  } catch (error) {
    console.error("Telegram initData verification failed:", error);
    return null;
  }
}

async function getAuth(request, env) {
  const initData =
    request.headers.get("X-Telegram-Init-Data") || "";

  const verified = await verifyTelegramInitData(
    initData,
    env.BOT_TOKEN
  );

  if (!verified?.user?.id) {
    return {
      error: json(
        { error: "Open this app from Telegram." },
        401
      )
    };
  }

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

async function ensureUser(db, user, startParam, env) {
  const id = String(user.id);

  const existing = await db.prepare(
    "SELECT telegram_id FROM users WHERE telegram_id = ?"
  ).bind(id).first();

  if (existing) {
    await db.prepare(
      "UPDATE users SET username = ?, first_name = ? WHERE telegram_id = ?"
    ).bind(
      user.username || "",
      user.first_name || "",
      id
    ).run();

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
    INSERT INTO users
      (telegram_id, username, first_name, referred_by)
    VALUES (?, ?, ?, ?)
  `).bind(
    id,
    user.username || "",
    user.first_name || "",
    referrer || null
  ).run();

  // Referral rewards are not paid at signup. They are awarded only after
  // this referred user has at least one admin-approved task.

  return id;
}

async function isMember(env, chatId, userId) {
  if (!chatId) return false;

  const member = await telegramRequest(
    env,
    "getChatMember",
    {
      chat_id: chatId,
      user_id: Number(userId)
    }
  );

  return (
    ["creator", "administrator", "member"].includes(member.status) ||
    (member.status === "restricted" && member.is_member === true)
  );
}

async function awardReferralReward(db, referredTelegramId, env) {
  const referred = await db.prepare(`
    SELECT referred_by, first_name
    FROM users
    WHERE telegram_id = ?
  `).bind(String(referredTelegramId)).first();

  const referrerId = referred?.referred_by ? String(referred.referred_by) : "";
  if (!referrerId || referrerId === String(referredTelegramId)) return false;

  const completed = await db.prepare(`
    SELECT COUNT(*) AS count
    FROM task_claims
    WHERE telegram_id = ? AND status = 'approved'
  `).bind(String(referredTelegramId)).first();
  if (Number(completed?.count || 0) < 1) return false;

  // A partial unique index makes the reward idempotent for each referred user.
  try {
    await db.prepare(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_referral_reward_once
      ON ledger (telegram_id, reference)
      WHERE kind = 'referral_reward'
    `).run();
  } catch (error) {
    // Do not prevent task approval if an older database has conflicting rows.
    console.error("Could not create referral reward index:", error);
  }

  const inserted = await db.prepare(`
    INSERT INTO ledger (telegram_id, amount, kind, reference)
    SELECT ?, 0.010, 'referral_reward', ?
    WHERE NOT EXISTS (
      SELECT 1 FROM ledger
      WHERE telegram_id = ? AND kind = 'referral_reward' AND reference = ?
    )
  `).bind(referrerId, String(referredTelegramId), referrerId, String(referredTelegramId)).run();

  if (!inserted.meta.changes) return false;

  await db.prepare(`
    UPDATE users
    SET balance = balance + 0.010,
        total_earned = total_earned + 0.010
    WHERE telegram_id = ?
  `).bind(referrerId).run();

  try {
    await telegramRequest(env, "sendMessage", {
      chat_id: referrerId,
      text: `🎉 Your friend ${referred.first_name || ""} completed their first approved task. You earned a $0.010 referral bonus!`
    });
  } catch (error) {
    console.error("Referral reward notification failed:", error);
  }
  return true;
}

async function handleApi(request, env, url) {
  const db = env.DB;
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // ADMIN API
  if (path.startsWith("/api/admin/")) {
    if (!isAdmin(request, env)) {
      return json({ error: "Unauthorized" }, 401);
    }

    if (path === "/api/admin/overview" && method === "GET") {
      const [
        users,
        tasks,
        claims,
        withdrawals,
        requests
      ] = await Promise.all([
        db.prepare(
          "SELECT COUNT(*) count FROM users"
        ).first(),

        db.prepare(
          "SELECT COUNT(*) count FROM tasks WHERE active = 1"
        ).first(),

        db.prepare(
          "SELECT COUNT(*) count FROM task_claims WHERE status = 'pending'"
        ).first(),

        db.prepare(
          "SELECT COUNT(*) count FROM withdrawals WHERE status = 'pending'"
        ).first(),

        db.prepare(`
          SELECT COUNT(*) count FROM task_requests
          WHERE status IN ('awaiting_payment', 'pending_review')
        `).first()
      ]);

      return json({
        users: users.count,
        tasks: tasks.count,
        pendingClaims: claims.count,
        pendingWithdrawals: withdrawals.count,
        pendingTaskRequests: requests.count
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

      const taskType = ["link", "channel", "group"].includes(
        body.task_type
      ) ? body.task_type : "link";

      const chatId = String(body.chat_id || "").trim();

      if (
        !title ||
        !Number.isFinite(reward) ||
        reward <= 0 ||
        reward > 100
      ) {
        return json(
          { error: "Enter a valid title and reward." },
          400
        );
      }

      if (taskType !== "link" && !chatId) {
        return json(
          {
            error:
              "Enter the Telegram channel/group username or chat ID."
          },
          400
        );
      }

      await db.prepare(`
        INSERT INTO tasks
          (title, description, url, reward, active, task_type, chat_id)
        VALUES (?, ?, ?, ?, 1, ?, ?)
      `).bind(
        title,
        description,
        taskUrl,
        reward,
        taskType,
        chatId
      ).run();

      return json({ ok: true });
    }

    const removeTask = path.match(
      /^\/api\/admin\/tasks\/(\d+)$/
    );

    if (removeTask && method === "POST") {
      await db.prepare(
        "UPDATE tasks SET active = 0 WHERE id = ?"
      ).bind(Number(removeTask[1])).run();

      return json({ ok: true });
    }

    if (path === "/api/admin/claims" && method === "GET") {
      const result = await db.prepare(`
        SELECT
          c.id,
          c.telegram_id,
          c.task_id,
          c.status,
          c.proof,
          c.created_at,
          t.title,
          t.reward
        FROM task_claims c
        JOIN tasks t ON t.id = c.task_id
        WHERE c.status = 'pending'
        ORDER BY c.id DESC
      `).all();

      return json(result.results);
    }

    const reviewClaim = path.match(
      /^\/api\/admin\/claims\/(\d+)\/(approve|reject)$/
    );

    if (reviewClaim && method === "POST") {
      const id = Number(reviewClaim[1]);
      const action = reviewClaim[2];

      const claim = await db.prepare(`
        SELECT c.*, t.reward
        FROM task_claims c
        JOIN tasks t ON t.id = c.task_id
        WHERE c.id = ? AND c.status = 'pending'
      `).bind(id).first();

      if (!claim) {
        return json(
          { error: "Claim not found or already reviewed." },
          404
        );
      }

      if (action === "approve") {
        const update = await db.prepare(`
          UPDATE task_claims
          SET status = 'approved'
          WHERE id = ? AND status = 'pending'
        `).bind(id).run();

        if (!update.meta.changes) {
          return json({ error: "Already reviewed." }, 409);
        }

        await db.batch([
          db.prepare(`
            UPDATE users
            SET balance = balance + ?,
                total_earned = total_earned + ?
            WHERE telegram_id = ?
          `).bind(
            claim.reward,
            claim.reward,
            claim.telegram_id
          ),

          db.prepare(`
            INSERT INTO ledger
              (telegram_id, amount, kind, reference)
            VALUES (?, ?, 'task_reward', ?)
          `).bind(
            claim.telegram_id,
            claim.reward,
            String(id)
          )
        ]);

        await awardReferralReward(db, claim.telegram_id, env);
      } else {
        const update = await db.prepare(`
          UPDATE task_claims
          SET status = 'rejected'
          WHERE id = ? AND status = 'pending'
        `).bind(id).run();

        if (!update.meta.changes) {
          return json({ error: "Already reviewed." }, 409);
        }
      }

      return json({ ok: true });
    }

    // USER-SUBMITTED TASK REQUESTS
    if (path === "/api/admin/task-requests" && method === "GET") {
      const result = await db.prepare(
        "SELECT * FROM task_requests ORDER BY id DESC"
      ).all();

      return json(result.results);
    }

    const reviewRequest = path.match(
      /^\/api\/admin\/task-requests\/(\d+)\/(approve|reject)$/
    );

    if (reviewRequest && method === "POST") {
      const id = Number(reviewRequest[1]);
      const action = reviewRequest[2];

      const taskRequest = await db.prepare(`
        SELECT *
        FROM task_requests
        WHERE id = ? AND status = 'pending_review'
      `).bind(id).first();

      if (!taskRequest) {
        return json(
          {
            error:
              "Request not found or payment has not been submitted."
          },
          404
        );
      }

      if (action === "approve") {
        const updated = await db.prepare(`
          UPDATE task_requests
          SET status = 'approved',
              reviewed_at = CURRENT_TIMESTAMP
          WHERE id = ? AND status = 'pending_review'
        `).bind(id).run();

        if (!updated.meta.changes) {
          return json({ error: "Request already reviewed." }, 409);
        }

        const targetUrl = taskRequest.target_url;
        const usernameMatch = targetUrl.match(
          /t\.me\/([A-Za-z0-9_]+)/i
        );

        const chatId = usernameMatch
          ? "@" + usernameMatch[1]
          : "";

        const taskType = chatId ? "channel" : "link";

        await db.prepare(`
          INSERT INTO tasks
            (title, description, url, reward, active, task_type, chat_id)
          VALUES (?, ?, ?, 0.02, 1, ?, ?)
        `).bind(
          taskRequest.title,
          taskRequest.description,
          targetUrl,
          taskType,
          chatId
        ).run();

        try {
          await telegramRequest(env, "sendMessage", {
            chat_id: taskRequest.telegram_id,
            text:
              `✅ Your task request #${id} was approved ` +
              "and added to TaskPay."
          });
        } catch (error) {
          console.error("Approval notification failed:", error);
        }
      } else {
        const updated = await db.prepare(`
          UPDATE task_requests
          SET status = 'rejected',
              reviewed_at = CURRENT_TIMESTAMP
          WHERE id = ? AND status = 'pending_review'
        `).bind(id).run();

        if (!updated.meta.changes) {
          return json({ error: "Request already reviewed." }, 409);
        }

        try {
          await telegramRequest(env, "sendMessage", {
            chat_id: taskRequest.telegram_id,
            text:
              `❌ Your task request #${id} was rejected. ` +
              "Please contact Help Center for details."
          });
        } catch (error) {
          console.error("Rejection notification failed:", error);
        }
      }

      return json({ ok: true });
    }

    // WITHDRAWALS
    if (path === "/api/admin/withdrawals" && method === "GET") {
      const result = await db.prepare(
        "SELECT * FROM withdrawals ORDER BY id DESC"
      ).all();

      return json(result.results);
    }

    const reviewWithdrawal = path.match(
      /^\/api\/admin\/withdrawals\/(\d+)\/(approve|reject)$/
    );

    if (reviewWithdrawal && method === "POST") {
      const id = Number(reviewWithdrawal[1]);
      const action = reviewWithdrawal[2];

      const withdrawal = await db.prepare(`
        SELECT *
        FROM withdrawals
        WHERE id = ? AND status = 'pending'
      `).bind(id).first();

      if (!withdrawal) {
        return json(
          { error: "Withdrawal not found or already reviewed." },
          404
        );
      }

      if (action === "approve") {
        const updated = await db.prepare(`
          UPDATE withdrawals
          SET status = 'approved',
              reviewed_at = CURRENT_TIMESTAMP
          WHERE id = ? AND status = 'pending'
        `).bind(id).run();

        if (!updated.meta.changes) {
          return json({ error: "Already reviewed." }, 409);
        }

        if (env.PROOF_CHANNEL_ID) {
          try {
            await telegramRequest(env, "sendMessage", {
              chat_id: env.PROOF_CHANNEL_ID,
              text:
                `✅ Withdrawal approved\n` +
                `Request: #${id}\n` +
                `User ID: ${withdrawal.telegram_id}\n` +
                `Amount: $${Number(withdrawal.amount).toFixed(3)}\n` +
                `Binance ID: ${withdrawal.binance_id}\n\n` +
                "Please send the payment manually."
            });
          } catch (error) {
            console.error("Withdrawal notification failed:", error);
          }
        }
      } else {
        const updated = await db.prepare(`
          UPDATE withdrawals
          SET status = 'rejected',
              reviewed_at = CURRENT_TIMESTAMP
          WHERE id = ? AND status = 'pending'
        `).bind(id).run();

        if (!updated.meta.changes) {
          return json({ error: "Already reviewed." }, 409);
        }

        await db.prepare(`
          UPDATE users
          SET balance = balance + ?
          WHERE telegram_id = ?
        `).bind(
          withdrawal.amount,
          withdrawal.telegram_id
        ).run();
      }

      return json({ ok: true });
    }

    if (path === "/api/admin/users" && method === "GET") {
      const result = await db.prepare(`
        SELECT
          telegram_id,
          username,
          first_name,
          balance,
          total_earned,
          referred_by,
          created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 500
      `).all();

      return json(result.results);
    }

    return json({ error: "Admin route not found." }, 404);
  }

  // ADSUN SERVER REWARD CALLBACK. This route runs before Telegram Mini App
  // authentication because Adsun calls it server-to-server without initData.
  if (path === "/api/ads/reward" && method === "GET") {
    const expectedSecret = String(env.ADSUN_REWARD_SECRET || "");
    const suppliedSecret = String(url.searchParams.get("key") || "");
    const callbackUserId = String(url.searchParams.get("userid") || url.searchParams.get("user") || "");
    const callbackBlockId = String(url.searchParams.get("block") || url.searchParams.get("blockId") || "");
    const callbackTimestamp = String(url.searchParams.get("timestamp") || "");

    if (!expectedSecret || suppliedSecret !== expectedSecret) {
      return json({ error: "Unauthorized callback." }, 401);
    }
    if (!/^\d{1,20}$/.test(callbackUserId)) {
      return json({ error: "Invalid user ID." }, 400);
    }
    if (callbackBlockId !== "50075") {
      return json({ error: "Unexpected Adsun block ID." }, 400);
    }
    if (!/^\d{9,12}$/.test(callbackTimestamp)) {
      return json({ error: "Invalid reward timestamp." }, 400);
    }
    const callbackTimeMs = Number(callbackTimestamp) * 1000;
    if (!Number.isFinite(callbackTimeMs) || callbackTimeMs > Date.now() + 5 * 60 * 1000 || Date.now() - callbackTimeMs > 24 * 60 * 60 * 1000) {
      return json({ error: "Expired reward callback." }, 400);
    }

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS daily_ads (
        telegram_id TEXT NOT NULL,
        ad_date TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (telegram_id, ad_date)
      )
    `).run();
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS ad_reward_sessions (
        telegram_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL UNIQUE,
        started_at INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        rewarded_at INTEGER,
        reward_token TEXT
      )
    `).run();
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS ad_reward_events (
        session_id TEXT PRIMARY KEY,
        telegram_id TEXT NOT NULL,
        ad_date TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at INTEGER NOT NULL,
        reward_token TEXT NOT NULL UNIQUE
      )
    `).run();

    const now = Date.now();
    const today = new Date().toISOString().slice(0, 10);
    const token = crypto.randomUUID();
    const session = await db.prepare(`
      SELECT session_id, started_at, status
      FROM ad_reward_sessions WHERE telegram_id = ?
    `).bind(callbackUserId).first();

    if (!session || session.status !== "pending" ||
        now < Number(session.started_at) ||
        now - Number(session.started_at) > 10 * 60 * 1000 ||
        callbackTimeMs < Number(session.started_at) - 60 * 1000 ||
        callbackTimeMs > Number(session.started_at) + 15 * 60 * 1000) {
      return json({ ok: true, rewarded: false, reason: "No valid pending ad session." });
    }

    // D1 batch runs atomically. A unique session/event and one-time pending->rewarded
    // transition prevent replaying the same callback to earn a second reward.
    await db.batch([
      db.prepare(`
        UPDATE ad_reward_sessions
        SET status = 'rewarded', rewarded_at = ?, reward_token = ?
        WHERE telegram_id = ? AND session_id = ? AND status = 'pending'
          AND started_at <= ? AND started_at >= ?
          AND NOT EXISTS (
            SELECT 1 FROM daily_ads
            WHERE telegram_id = ? AND ad_date = ? AND count >= 100
          )
      `).bind(now, token, callbackUserId, session.session_id, now,
        now - 10 * 60 * 1000, callbackUserId, today),
      db.prepare(`
        INSERT OR IGNORE INTO ad_reward_events
          (session_id, telegram_id, ad_date, amount, created_at, reward_token)
        SELECT session_id, telegram_id, ?, 0.010, ?, ?
        FROM ad_reward_sessions
        WHERE telegram_id = ? AND session_id = ? AND status = 'rewarded'
          AND reward_token = ? AND rewarded_at = ?
          AND NOT EXISTS (
            SELECT 1 FROM daily_ads
            WHERE telegram_id = ? AND ad_date = ? AND count >= 100
          )
      `).bind(today, now, token, callbackUserId, session.session_id,
        token, now, callbackUserId, today),
      db.prepare(`
        INSERT INTO daily_ads (telegram_id, ad_date, count)
        SELECT telegram_id, ad_date, 1 FROM ad_reward_events
        WHERE session_id = ? AND reward_token = ?
        ON CONFLICT (telegram_id, ad_date)
        DO UPDATE SET count = count + 1 WHERE count < 100
      `).bind(session.session_id, token),
      db.prepare(`
        UPDATE users
        SET balance = balance + 0.010,
            total_earned = total_earned + 0.010
        WHERE telegram_id = ? AND EXISTS (
          SELECT 1 FROM ad_reward_events
          WHERE session_id = ? AND reward_token = ?
        )
      `).bind(callbackUserId, session.session_id, token),
      db.prepare(`
        INSERT INTO ledger (telegram_id, amount, kind, reference)
        SELECT ?, 0.010, 'ad_reward', ?
        WHERE EXISTS (
          SELECT 1 FROM ad_reward_events
          WHERE session_id = ? AND reward_token = ?
        )
          AND NOT EXISTS (
            SELECT 1 FROM ledger WHERE kind = 'ad_reward' AND reference = ?
          )
      `).bind(callbackUserId, session.session_id, session.session_id, token,
        session.session_id)
    ]);

    const event = await db.prepare(`
      SELECT session_id FROM ad_reward_events
      WHERE session_id = ? AND reward_token = ?
    `).bind(session.session_id, token).first();

    return json({ ok: true, rewarded: Boolean(event) });
  }

  // TELEGRAM USER AUTHENTICATION
  const auth = await getAuth(request, env);
  if (auth.error) return auth.error;

  const user = auth.user;

  const telegramId = await ensureUser(
    db,
    user,
    auth.startParam,
    env
  );

  // CONFIGURATION
  if (path === "/api/config" && method === "GET") {
    return json({
      botUsername: env.BOT_USERNAME || "task_v1_bot",
      officialChannel: "https://t.me/flash_bot_update",
      usdtAddress: env.USDT_BEP20_ADDRESS || ""
    });
  }

  // PROFILE
  if (path === "/api/me" && method === "GET") {
    const me = await db.prepare(`
      SELECT
        telegram_id,
        username,
        first_name,
        balance,
        total_earned,
        created_at,
        last_daily_claim
      FROM users
      WHERE telegram_id = ?
    `).bind(telegramId).first();

    const [referrals, verifiedReferrals, completedTasks, referralEarnings, friends] = await Promise.all([
      db.prepare(`SELECT COUNT(*) AS count FROM users WHERE referred_by = ?`).bind(telegramId).first(),
      db.prepare(`
        SELECT COUNT(DISTINCT u.telegram_id) AS count
        FROM users u
        JOIN task_claims c ON c.telegram_id = u.telegram_id AND c.status = 'approved'
        WHERE u.referred_by = ?
      `).bind(telegramId).first(),
      db.prepare(`
        SELECT COUNT(*) AS count FROM task_claims
        WHERE telegram_id = ? AND status = 'approved'
      `).bind(telegramId).first(),
      db.prepare(`
        SELECT COALESCE(SUM(amount), 0) AS total FROM ledger
        WHERE telegram_id = ? AND kind = 'referral_reward'
      `).bind(telegramId).first(),
      db.prepare(`
        SELECT u.telegram_id, u.username, u.first_name,
          CASE WHEN EXISTS (
            SELECT 1 FROM task_claims c
            WHERE c.telegram_id = u.telegram_id AND c.status = 'approved'
          ) THEN 'Verified' ELSE 'Unverified' END AS referral_status
        FROM users u
        WHERE u.referred_by = ?
        ORDER BY u.telegram_id DESC
        LIMIT 100
      `).bind(telegramId).all()
    ]);

    const totalReferrals = Number(referrals?.count || 0);
    const verifiedCount = Number(verifiedReferrals?.count || 0);
    return json({
      ...me,
      referrals: totalReferrals,
      verifiedReferrals: verifiedCount,
      unverifiedReferrals: Math.max(0, totalReferrals - verifiedCount),
      completedTasks: Number(completedTasks?.count || 0),
      referralEarnings: Number(referralEarnings?.total || 0),
      referredFriends: (friends.results || []).map(friend => ({
        telegramId: friend.telegram_id,
        username: friend.username || "",
        firstName: friend.first_name || "Friend",
        status: friend.referral_status
      }))
    });
  }

  // AVAILABLE TASKS
  if (path === "/api/tasks" && method === "GET") {
    const result = await db.prepare(`
      SELECT
        t.id,
        t.title,
        t.description,
        t.url,
        t.reward,
        t.task_type,
        t.chat_id,
        (
          SELECT status
          FROM task_claims c
          WHERE c.task_id = t.id
            AND c.telegram_id = ?
        ) claim_status
      FROM tasks t
      WHERE t.active = 1
      ORDER BY t.id DESC
    `).bind(telegramId).all();

    return json(result.results);
  }

  // CLAIM OR VERIFY A TASK
  if (path === "/api/task-claim" && method === "POST") {
    const body = await request.json();
    const taskId = Number(body.taskId);

    if (!Number.isInteger(taskId) || taskId < 1) {
      return json({ error: "Invalid task." }, 400);
    }

    const task = await db.prepare(`
      SELECT *
      FROM tasks
      WHERE id = ? AND active = 1
    `).bind(taskId).first();

    if (!task) {
      return json({ error: "Task is unavailable." }, 404);
    }

    // Regular URL tasks require admin review.
    if (
      !["channel", "group"].includes(task.task_type) ||
      !task.chat_id
    ) {
      const proof = String(body.proof || "").trim();

      try {
        await db.prepare(`
          INSERT INTO task_claims
            (telegram_id, task_id, proof)
          VALUES (?, ?, ?)
        `).bind(telegramId, taskId, proof).run();
      } catch {
        return json(
          { error: "You have already submitted this task." },
          409
        );
      }

      try {
        await notifyAdmin(
          env,
          `📝 Task submission\n` +
          `User ID: ${telegramId}\n` +
          `Task: ${task.title}\n` +
          `Proof: ${proof || "Not provided"}\n` +
          "Review this submission in the TaskPay Admin Panel."
        );
      } catch (error) {
        console.error("Task notification failed:", error);
      }

      return json({ ok: true, status: "pending" });
    }

    // Verify channel/group membership using Telegram.
    let member = false;

    try {
      member = await isMember(
        env,
        task.chat_id,
        telegramId
      );
    } catch (error) {
      console.error("Membership verification failed:", error);

      return json(
        {
          error:
            "Could not verify membership. Check that the bot " +
            "is an administrator in the channel/group and the chat ID is correct."
        },
        400
      );
    }

    if (!member) {
      return json(
        {
          error:
            "Join the channel/group first, then try again."
        },
        400
      );
    }

    // Unique(telegram_id, task_id) prevents duplicate rewards.
    try {
      const inserted = await db.prepare(`
        INSERT INTO task_claims
          (telegram_id, task_id, status, proof)
        VALUES (?, ?, 'approved', 'Telegram membership verified')
      `).bind(telegramId, taskId).run();

      if (!inserted.meta.changes) {
        return json({ error: "Task already completed." }, 409);
      }
    } catch {
      return json({ error: "Task already completed." }, 409);
    }

    await db.batch([
      db.prepare(`
        UPDATE users
        SET balance = balance + ?,
            total_earned = total_earned + ?
        WHERE telegram_id = ?
      `).bind(task.reward, task.reward, telegramId),

      db.prepare(`
        INSERT INTO ledger
          (telegram_id, amount, kind, reference)
        VALUES (?, ?, 'task_reward', ?)
      `).bind(
        telegramId,
        task.reward,
        String(taskId)
      )
    ]);

    await awardReferralReward(db, telegramId, env);

    return json({
      ok: true,
      status: "approved",
      reward: task.reward
    });
  }

  // DAILY ADSUN REWARDS. Client-side requests never credit a balance.
  if (["/api/ads/status", "/api/ads/start", "/api/ads/claim"].includes(path)) {
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS daily_ads (
        telegram_id TEXT NOT NULL,
        ad_date TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (telegram_id, ad_date)
      )
    `).run();
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS ad_reward_sessions (
        telegram_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL UNIQUE,
        started_at INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        rewarded_at INTEGER,
        reward_token TEXT
      )
    `).run();
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS ad_reward_events (
        session_id TEXT PRIMARY KEY,
        telegram_id TEXT NOT NULL,
        ad_date TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at INTEGER NOT NULL,
        reward_token TEXT NOT NULL UNIQUE
      )
    `).run();

    const today = new Date().toISOString().slice(0, 10);
    const daily = await db.prepare(`
      SELECT count FROM daily_ads WHERE telegram_id = ? AND ad_date = ?
    `).bind(String(telegramId), today).first();
    const count = Number(daily?.count || 0);

    if (path === "/api/ads/status" && method === "GET") {
      const session = await db.prepare(`
        SELECT started_at, status FROM ad_reward_sessions WHERE telegram_id = ?
      `).bind(String(telegramId)).first();
      const pending = Boolean(session && session.status === "pending" &&
        Date.now() >= Number(session.started_at) &&
        Date.now() - Number(session.started_at) <= 10 * 60 * 1000);
      return json({ count, started: pending, pending, rewardPerAd: 0.010, limit: 100 });
    }

    if (path === "/api/ads/start" && method === "POST") {
      if (count >= 100) return json({ error: "Come Again Tomorrow" }, 409);

      const existing = await db.prepare(`
        SELECT session_id, started_at, status
        FROM ad_reward_sessions WHERE telegram_id = ?
      `).bind(String(telegramId)).first();
      if (existing && existing.status === "pending" &&
          Date.now() >= Number(existing.started_at) &&
          Date.now() - Number(existing.started_at) <= 10 * 60 * 1000) {
        return json({ ok: true, started: true, pending: true });
      }

      await db.prepare(`
        INSERT INTO ad_reward_sessions
          (telegram_id, session_id, started_at, status, rewarded_at, reward_token)
        VALUES (?, ?, ?, 'pending', NULL, NULL)
        ON CONFLICT (telegram_id) DO UPDATE SET
          session_id = excluded.session_id,
          started_at = excluded.started_at,
          status = 'pending', rewarded_at = NULL, reward_token = NULL
      `).bind(String(telegramId), crypto.randomUUID(), Date.now()).run();
      return json({ ok: true, started: true, pending: true });
    }

    if (path === "/api/ads/claim" && method === "POST") {
      return json({
        error: "Rewards are confirmed by the Adsun server callback.",
        pending: true
      }, 409);
    }
  }

  // DAILY REWARD
  if (path === "/api/daily-claim" && method === "POST") {
    const today = new Date().toISOString().slice(0, 10);

    const result = await db.prepare(`
      UPDATE users
      SET balance = balance + 0.015,
          total_earned = total_earned + 0.015,
          last_daily_claim = ?
      WHERE telegram_id = ?
        AND (
          last_daily_claim IS NULL
          OR last_daily_claim < ?
        )
    `).bind(
      today,
      telegramId,
      today
    ).run();

    if (!result.meta.changes) {
      return json(
        { error: "Daily reward already claimed today." },
        409
      );
    }

    await db.prepare(`
      INSERT INTO ledger
        (telegram_id, amount, kind)
      VALUES (?, 0.015, 'daily_claim')
    `).bind(telegramId).run();

    return json({ ok: true, reward: 0.015 });
  }

  // SUBMIT A PAID TASK REQUEST
  if (path === "/api/task-requests" && method === "POST") {
    const body = await request.json();

    const title = String(body.title || "").trim();
    const description = String(body.description || "").trim();
    const targetUrl = String(body.targetUrl || "").trim();

    const memberCount = Number(body.memberCount);
    const taxId = String(body.taxId || "").trim();
    const paymentTxId = String(body.paymentTxId || "").trim();

    if (title.length < 3 || title.length > 120) {
      return json(
        { error: "Task title must be 3–120 characters." },
        400
      );
    }

    if (
      !Number.isSafeInteger(memberCount) ||
      memberCount < 1
    ) {
      return json(
        { error: "Enter a valid target member count." },
        400
      );
    }

    if (
      !/^https:\/\/t\.me\/[A-Za-z0-9_+/-]+\/?$/i.test(targetUrl)
    ) {
      return json(
        { error: "Enter a valid Telegram link." },
        400
      );
    }

    if (!taxId || taxId.length > 100) {
      return json({ error: "Enter your Tax ID." }, 400);
    }

    if (
      paymentTxId.length < 8 ||
      paymentTxId.length > 200
    ) {
      return json(
        {
          error:
            "Enter the USDT BEP20 transaction hash after payment."
        },
        400
      );
    }

    const address = String(
      env.USDT_BEP20_ADDRESS || ""
    ).trim();

    if (!address) {
      return json(
        {
          error:
            "USDT payment address is not configured yet. Please contact Help Center."
        },
        400
      );
    }

    const price = memberCount > 2000 ? 6 : 4;

    const result = await db.prepare(`
      INSERT INTO task_requests (
        telegram_id,
        title,
        description,
        target_url,
        member_count,
        price_usd,
        tax_id,
        payment_txid,
        status
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_review')
    `).bind(
      telegramId,
      title,
      description,
      targetUrl,
      memberCount,
      price,
      taxId,
      paymentTxId
    ).run();

    const requestId = result.meta.last_row_id;

    try {
      await notifyAdmin(
        env,
        `💳 New Task Request #${requestId}\n` +
        `User ID: ${telegramId}\n` +
        `Title: ${title}\n` +
        `Target: ${targetUrl}\n` +
        `Members: ${memberCount}\n` +
        `Price: $${price}\n` +
        `Tax ID: ${taxId}\n` +
        `TXID: ${paymentTxId}\n\n` +
        "Verify the transaction manually before approving."
      );
    } catch (error) {
      console.error("Task request notification failed:", error);
    }

    return json({
      ok: true,
      requestId,
      price,
      status: "pending_review"
    });
  }

  // HELP CENTER
  if (path === "/api/help" && method === "POST") {
    const body = await request.json();
    const message = String(body.message || "").trim();

    if (message.length < 2 || message.length > 2000) {
      return json(
        { error: "Message must be 2–2000 characters." },
        400
      );
    }

    await db.prepare(`
      INSERT INTO help_messages
        (telegram_id, username, first_name, message)
      VALUES (?, ?, ?, ?)
    `).bind(
      telegramId,
      user.username || "",
      user.first_name || "",
      message
    ).run();

    try {
      await notifyAdmin(
        env,
        `📩 TaskPay Help Center\n` +
        `Name: ${user.first_name || "User"}\n` +
        `Username: ${user.username ? "@" + user.username : "Not set"}\n` +
        `Telegram ID: ${telegramId}\n\n` +
        `Message:\n${message}`
      );
    } catch (error) {
      console.error("Help notification failed:", error);

      return json(
        {
          error:
            "Your message was saved, but notification failed. Please try again later."
        },
        502
      );
    }

    return json({ ok: true });
  }

  // WITHDRAWAL REQUEST
  if (path === "/api/withdraw" && method === "POST") {
    const body = await request.json();

    const amount = Number(body.amount);
    const binanceId = String(body.binanceId || "").trim();

    if (
      !Number.isFinite(amount) ||
      amount < 5 ||
      amount > 100000
    ) {
      return json(
        { error: "Minimum withdrawal is $5.00." },
        400
      );
    }

    if (binanceId.length < 2 || binanceId.length > 100) {
      return json({ error: "Enter a valid Binance ID." }, 400);
    }

    const pending = await db.prepare(`
      SELECT id
      FROM withdrawals
      WHERE telegram_id = ? AND status = 'pending'
    `).bind(telegramId).first();

    if (pending) {
      return json(
        { error: "You already have a pending withdrawal." },
        409
      );
    }

    const debit = await db.prepare(`
      UPDATE users
      SET balance = balance - ?
      WHERE telegram_id = ? AND balance >= ?
    `).bind(
      amount,
      telegramId,
      amount
    ).run();

    if (!debit.meta.changes) {
      return json({ error: "Insufficient balance." }, 400);
    }

    let inserted;

    try {
      inserted = await db.prepare(`
        INSERT INTO withdrawals
          (telegram_id, amount, binance_id)
        VALUES (?, ?, ?)
      `).bind(
        telegramId,
        amount,
        binanceId
      ).run();
    } catch (error) {
      // Refund if the request could not be created.
      await db.prepare(`
        UPDATE users
        SET balance = balance + ?
        WHERE telegram_id = ?
      `).bind(amount, telegramId).run();

      throw error;
    }

    try {
      await notifyAdmin(
        env,
        `💸 Withdrawal Request #${inserted.meta.last_row_id}\n` +
        `User ID: ${telegramId}\n` +
        `Amount: $${amount.toFixed(3)}\n` +
        `Binance ID: ${binanceId}`
      );
    } catch (error) {
      console.error("Withdrawal notification failed:", error);
    }

    return json({
      ok: true,
      status: "pending",
      withdrawalId: inserted.meta.last_row_id
    });
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
        console.error("Worker error:", error);

        return json(
          { error: "Server error. Check Worker logs." },
          500
        );
      }
    }

    if (url.pathname === "/health") {
      return json({ ok: true, app: "TaskPay" });
    }

    return env.ASSETS.fetch(request);
  }
};
