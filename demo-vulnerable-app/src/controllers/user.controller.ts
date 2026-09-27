import { Request, Response } from 'express';
import { JWT_SECRET } from '../config/auth.config.js';

// Simulated DB driver with parameterized query support
const mockDb = {
  query: async (sql: string, params: any[] = []) => {
    console.log(`[Database Executed]: ${sql} with params: ${JSON.stringify(params)}`);
    return [{ id: '1', username: 'admin', role: 'administrator', email: 'admin@company.corp' }];
  },
};

/**
 * Handles user login.
 * ✅ REMEDIATED: SQL Injection resolved with parameterized queries.
 * ✅ REMEDIATED: Insecure error handling resolved with generic 500 error.
 */
export async function loginUser(req: Request, res: Response) {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const sql = 'SELECT id, username, role, email FROM users WHERE username = $1 AND password = $2';
    const users = await mockDb.query(sql, [username, password]);

    if (!users || users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({ success: true, token: 'jwt-token-sample', user: users[0] });
  } catch (err: any) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'An internal authentication error occurred' });
  }
}

/**
 * Retrieves sensitive user billing record.
 * ✅ REMEDIATED: Missing Authorization (IDOR) resolved with strict ownership & role verification.
 */
export async function getUserBilling(req: Request, res: Response) {
  const targetUserId = req.params.userId;
  // Simulated authenticated user context from verified JWT / session
  const currentUser = (req as any).user || { id: '1', role: 'user' };

  // Strict Authorization Check: Users can only view their own billing data, unless administrator
  if (currentUser.id !== targetUserId && currentUser.role !== 'administrator') {
    return res.status(403).json({ error: 'Access denied: You do not have permission to view this billing record' });
  }

  const billingInfo = {
    userId: targetUserId,
    creditCard: '4111-XXXX-XXXX-1111',
    billingAddress: '123 Enterprise Way, Suite 400',
    currentBalance: 1450.0,
  };

  res.json({ success: true, billing: billingInfo });
}
