ALTER TABLE tasks ADD COLUMN task_type TEXT NOT NULL DEFAULT 'link';
ALTER TABLE tasks ADD COLUMN chat_id TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS task_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    target_url TEXT NOT NULL DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0,
    price_usd REAL NOT NULL DEFAULT 4,
    tax_id TEXT NOT NULL DEFAULT '',
    payment_txid TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'awaiting_payment',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS help_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    first_name TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'sent',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_task_requests_status
ON task_requests(status);

CREATE INDEX IF NOT EXISTS idx_help_messages_user
ON help_messages(telegram_id);
