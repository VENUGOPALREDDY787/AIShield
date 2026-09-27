import React from 'react';

interface BadgeProps {
  label: string;
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'warning' | 'neutral' | 'success' | 'danger' | string;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({ label, variant = 'neutral', size = 'md' }) => {
  const normVariant = variant.toLowerCase();
  let className = `badge badge-${normVariant}`;

  if (normVariant === 'pass' || normVariant === 'succeeded' || normVariant === 'improving' || normVariant === 'fixed') {
    className = 'badge badge-success';
  } else if (normVariant === 'fail' || normVariant === 'failed' || normVariant === 'worsening') {
    className = 'badge badge-danger';
  } else if (normVariant === 'warn' || normVariant === 'warning' || normVariant === 'queued' || normVariant === 'running') {
    className = 'badge badge-warning';
  }

  if (size === 'sm') {
    className += ' badge-sm';
  }

  return <span className={className}>{label}</span>;
};
