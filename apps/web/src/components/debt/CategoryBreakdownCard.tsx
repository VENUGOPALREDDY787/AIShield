import React from 'react';

interface CategoryBreakdownCardProps {
  categories: Record<string, number>;
}

export const CategoryBreakdownCard: React.FC<CategoryBreakdownCardProps> = ({ categories }) => {
  const entries = Object.entries(categories).sort((a, b) => b[1] - a[1]);
  const maxCount = Math.max(...Object.values(categories), 1);

  const formatCategoryName = (cat: string) => {
    return cat
      .split('_')
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  };

  return (
    <div className="card category-card">
      <div className="card-header">
        <h3>Top Contributing Debt Categories</h3>
        <span className="info-tooltip">{entries.length} categories</span>
      </div>

      {entries.length === 0 ? (
        <p className="empty-state">No categorized findings.</p>
      ) : (
        <div className="category-list">
          {entries.map(([category, count]) => {
            const widthPct = Math.max(Math.round((count / maxCount) * 100), 8);
            return (
              <div key={category} className="category-row">
                <div className="category-meta">
                  <span className="category-name">{formatCategoryName(category)}</span>
                  <span className="category-count">{count} findings</span>
                </div>
                <div className="category-bar-track">
                  <div className="category-bar-fill" style={{ width: `${widthPct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
