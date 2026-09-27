import express, { Request, Response } from 'express';
import { loginUser, getUserBilling } from './controllers/user.controller.js';
import { pingHost, viewLogFile } from './controllers/admin.controller.js';
import { searchProducts } from './controllers/search.controller.js';
import { handleLegacyAuth } from './controllers/crypto.controller.js';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'demo-app', timestamp: new Date().toISOString() });
});

// User Portal Routes (Introduced in PR 1)
app.post('/api/auth/login', loginUser);
app.get('/api/users/:userId/billing', getUserBilling);

// Admin Diagnostics & Search & Crypto (Introduced in PR 2)
app.get('/api/admin/ping', pingHost);
app.get('/api/admin/logs', viewLogFile);
app.get('/api/search', searchProducts);
app.post('/api/legacy/auth', handleLegacyAuth);

if (process.env.NODE_ENV !== 'test') {
  app.listen(port, () => {
    console.log(`Demo app running on http://localhost:${port}`);
  });
}

export default app;
