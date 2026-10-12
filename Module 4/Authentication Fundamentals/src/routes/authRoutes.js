const express = require('express');
const bcrypt = require('bcryptjs');
const prisma = require('../db/prisma');

const router = express.Router();
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const safeUser = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
});

router.post('/register', async (req, res, next) => {
  try {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!name || !emailRegex.test(email) || password.length < 8) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Name, valid email, and password (8+ chars) are required',
        },
      });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(409).json({
        error: { code: 'USER_ALREADY_EXISTS', message: 'User already exists' },
      });
    }

    const passwordHash = await bcrypt.hash(password, Number(process.env.BCRYPT_COST || 12));
    const createdUser = await prisma.user.create({
      data: { name, email, passwordHash },
    });

    return res.status(201).json({
      message: 'User registered successfully',
      user: safeUser(createdUser),
    });
  } catch (error) {
    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!emailRegex.test(email) || !password) {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' },
      });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' },
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' },
      });
    }

    return res.status(200).json({
      message: 'Login successful',
      user: safeUser(user),
    });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
