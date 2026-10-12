const prisma = require('../db/prisma');
const sessionStore = require('../session/sessionStore');

const AUTH_REQUIRED = {
  error: { code: 'AUTH_REQUIRED', message: 'Authentication required' },
};

module.exports = async function requireSession(req, res, next) {
  const sid = req.signedCookies?.sid;

  if (!sid) {
    return res.status(401).json(AUTH_REQUIRED);
  }

  const session = sessionStore.getSession(sid);
  if (!session) {
    return res.status(401).json(AUTH_REQUIRED);
  }

  const user = await prisma.user.findUnique({
    where: { id: session.userId },
    select: { id: true, name: true, email: true },
  });

  if (!user) {
    sessionStore.destroySession(sid);
    return res.status(401).json(AUTH_REQUIRED);
  }

  req.session = session;
  req.user = user;
  next();
};
