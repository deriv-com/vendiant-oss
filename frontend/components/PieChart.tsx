'use client';

import React, { useEffect, useRef } from 'react';

interface PieChartProps {
  data: {
    active: number;
    inactive: number;
  };
}

const PieChart: React.FC<PieChartProps> = ({ data }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    const size = 200;
    canvas.width = size;
    canvas.height = size;

    // Clear canvas
    ctx.clearRect(0, 0, size, size);

    // Ensure we have valid numbers
    const activeCount = parseInt(String(data.active)) || 0;
    const inactiveCount = parseInt(String(data.inactive)) || 0;
    const total = activeCount + inactiveCount;

    console.log('PieChart data:', { active: data.active, inactive: data.inactive, activeCount, inactiveCount, total });

    if (total === 0 || isNaN(total)) {
      // Draw empty state
      ctx.fillStyle = '#e5e7eb';
      ctx.beginPath();
      ctx.arc(size / 2, size / 2, size / 2 - 10, 0, 2 * Math.PI);
      ctx.fill();
      
      ctx.fillStyle = '#6b7280';
      ctx.font = '14px Inter';
      ctx.textAlign = 'center';
      ctx.fillText('No Data', size / 2, size / 2);
      return;
    }

    const centerX = size / 2;
    const centerY = size / 2;
    const radius = size / 2 - 10;

    // Calculate angles using the parsed numbers
    const activeAngle = (activeCount / total) * 2 * Math.PI;
    const inactiveAngle = (inactiveCount / total) * 2 * Math.PI;

    // Colors matching the original
    const activeColor = '#4ade80'; // var(--success-green)
    const inactiveColor = '#ef4444'; // var(--danger-red)

    let currentAngle = -Math.PI / 2; // Start from top

    // Draw active slice
    if (activeCount > 0) {
      ctx.fillStyle = activeColor;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + activeAngle);
      ctx.closePath();
      ctx.fill();
      currentAngle += activeAngle;
    }

    // Draw inactive slice
    if (inactiveCount > 0) {
      ctx.fillStyle = inactiveColor;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + inactiveAngle);
      ctx.closePath();
      ctx.fill();
    }

    // Draw white center circle with total count
    const innerRadius = radius * 0.6;
    ctx.fillStyle = 'white';
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerRadius, 0, 2 * Math.PI);
    ctx.fill();

    // Add border to inner circle
    ctx.strokeStyle = '#e5e7eb';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw total count text
    ctx.fillStyle = '#1f2937';
    ctx.font = 'bold 24px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total.toString(), centerX, centerY - 8);
    
    ctx.font = '12px Inter';
    ctx.fillStyle = '#6b7280';
    ctx.fillText('Total', centerX, centerY + 12);

  }, [data]);

  return (
    <div className="pie-chart-container">
      <canvas ref={canvasRef} className="pie-chart" />
      <div className="pie-chart-legend">
        <div className="legend-item">
          <div 
            className="legend-color" 
            style={{ backgroundColor: '#4ade80' }}
          ></div>
          <span>Active Subdomains</span>
        </div>
        <div className="legend-item">
          <div 
            className="legend-color" 
            style={{ backgroundColor: '#ef4444' }}
          ></div>
          <span>Inactive Subdomains</span>
        </div>
      </div>
    </div>
  );
};

export default PieChart; 