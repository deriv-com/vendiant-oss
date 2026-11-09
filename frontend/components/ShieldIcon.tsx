import React from 'react';

interface ShieldIconProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

const ShieldIcon: React.FC<ShieldIconProps> = ({ className = '', size = 'md' }) => {
  const sizeClasses = {
    sm: 'w-6 h-6',
    md: 'w-8 h-8', 
    lg: 'w-12 h-12',
    xl: 'w-16 h-16'
  };

  return (
    <svg 
      viewBox="0 0 24 24" 
      fill="currentColor" 
      className={`${sizeClasses[size]} ${className}`}
    >
      <path 
        fillRule="evenodd" 
        d="M12.516 2.17a.75.75 0 00-1.032 0 11.209 11.209 0 01-7.877 3.08.75.75 0 00-.722.515A12.74 12.74 0 002.25 9.75c0 5.814 3.051 10.077 9.75 12.98a.75.75 0 00.5 0c6.699-2.903 9.75-7.166 9.75-12.98 0-1.39-.223-2.73-.635-3.985a.75.75 0 00-.722-.515 11.209 11.209 0 01-7.877-3.08z" 
        clipRule="evenodd" 
      />
    </svg>
  );
};

export default ShieldIcon;
