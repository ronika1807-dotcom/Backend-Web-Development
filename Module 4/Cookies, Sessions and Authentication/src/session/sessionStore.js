const crypto = require('crypto');

const sessions = new Map();

function pruneExpiredSessions() {
  const now = Date.now();

  for (const [sid, session] of sessions.entries()) {
    if (session.expiresAt <= now) {
      sessions.delete(sid);
    }
  }
}

function createSession(userId) {
  const ttlMs = Number(process.env.SESSION_TTL_MS || 60 * 60 * 1000);
  const sid = crypto.randomBytes(24).toString('hex');

  sessions.set(sid, {
    userId,
    expiresAt: Date.now() + ttlMs,
  });

  return sid;
}

function getSession(sid) {
  if (!sid) return null;

  pruneExpiredSessions();

  const session = sessions.get(sid);
  if (!session) return null;

  if (session.expiresAt <= Date.now()) {
    sessions.delete(sid);
    return null;
  }

  return { ...session };
}

function destroySession(sid) {
  if (!sid) return false;

  return sessions.delete(sid);
}

module.exports = {
  createSession,
  getSession,
  destroySession,
};
