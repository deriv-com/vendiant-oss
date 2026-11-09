import React, { useState, useEffect } from 'react';
import { getVendorLogoUrls } from '../lib/vendor-utils';

interface VendorLogoImageProps {
  domain: string;
  vendorName: string;
  fallbackLogo?: string;
  className?: string;
  alt?: string;
  style?: React.CSSProperties;
}

/**
 * VendorLogoImage component that automatically tries multiple logo URLs
 * Falls back to showing vendor initial if all URLs fail
 */
const VendorLogoImage: React.FC<VendorLogoImageProps> = ({
  domain,
  vendorName,
  fallbackLogo,
  className = '',
  alt,
  style,
}) => {
  const [currentLogoIndex, setCurrentLogoIndex] = useState(0);
  const [allFailed, setAllFailed] = useState(false);
  
  // Get all possible logo URLs
  const logoUrls = fallbackLogo && !fallbackLogo.includes('clearbit')
    ? [fallbackLogo, ...getVendorLogoUrls(domain)]
    : getVendorLogoUrls(domain);
  
  const currentLogoUrl = logoUrls[currentLogoIndex];

  const handleImageError = () => {
    // Try next logo URL if available; otherwise render the React fallback UI.
    if (currentLogoIndex < logoUrls.length - 1) {
      setCurrentLogoIndex((prev) => prev + 1);
    } else {
      setAllFailed(true);
    }
  };

  // Reset when domain changes
  useEffect(() => {
    setCurrentLogoIndex(0);
    setAllFailed(false);
  }, [domain]);

  if (allFailed) {
    return (
      <div 
        className={className}
        style={{
          background: '#6366f1',
          color: 'white',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 600,
          fontSize: '1rem',
          width: '100%',
          height: '100%',
          borderRadius: '8px'
        }}
      >
        {vendorName.charAt(0).toUpperCase()}
      </div>
    );
  }

  if (!currentLogoUrl) {
    return null;
  }

  return (
    <img
      src={currentLogoUrl}
      alt={alt || `${vendorName} logo`}
      className={className}
      style={style}
      onError={handleImageError}
      key={currentLogoIndex} // Force re-render when URL changes
    />
  );
};

export default VendorLogoImage;

