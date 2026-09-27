import { Request, Response } from 'express';

function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Product & Content Search Endpoint.
 * ✅ REMEDIATED: Cross-Site Scripting (XSS) eliminated via contextual HTML entity escaping.
 */
export function searchProducts(req: Request, res: Response) {
  const rawQuery = (req.query.q as string) || '';
  const sanitizedQuery = escapeHtml(rawQuery);

  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>Search Results</title>
      </head>
      <body>
        <h1>Search Results for: ${sanitizedQuery}</h1>
        <p>No products found matching your search term.</p>
        <a href="/search">Try another search</a>
      </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.status(200).send(htmlResponse);
}
