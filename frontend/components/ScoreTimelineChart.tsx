'use client';

import React, { useEffect, useState } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale,
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import 'chartjs-adapter-date-fns';

// Hook to detect dark mode
const useDarkMode = () => {
  const [isDarkMode, setIsDarkMode] = useState(false);

  useEffect(() => {
    const checkDarkMode = () => {
      setIsDarkMode(document.body.classList.contains('dark-mode'));
    };

    // Initial check
    checkDarkMode();

    // Listen for changes
    const observer = new MutationObserver(checkDarkMode);
    observer.observe(document.body, {
      attributes: true,
      attributeFilter: ['class']
    });

    return () => observer.disconnect();
  }, []);

  return isDarkMode;
};

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  TimeScale
);

interface ScoreTimelineData {
  score: number;
  date: string;
  category: string;
  timestamp: number;
}

interface ScoreTimelineChartProps {
  domain: string;
  months?: number;
  category?: string;
  title?: string;
}

const ScoreTimelineChart: React.FC<ScoreTimelineChartProps> = ({
  domain,
  months = 3,
  category,
  title = 'Score Timeline (Past 3 Months)'
}) => {
  const [timelineData, setTimelineData] = useState<ScoreTimelineData[]>([]);
  const [loading, setLoading] = useState(true);
  const isDarkMode = useDarkMode();
  const [error, setError] = useState<string | null>(null);

  // Create gradient function
  const createGradient = (ctx: CanvasRenderingContext2D, chartArea: any) => {
    const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
    gradient.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
    gradient.addColorStop(0.3, 'rgba(59, 130, 246, 0.25)');
    gradient.addColorStop(0.7, 'rgba(59, 130, 246, 0.1)');
    gradient.addColorStop(1, 'rgba(59, 130, 246, 0.02)');
    return gradient;
  };

  useEffect(() => {
    fetchTimelineData();
  }, [domain, months, category]);

  const fetchTimelineData = async () => {
    try {
      setLoading(true);
      setError(null);

      const params = new URLSearchParams();
      if (months) params.append('months', months.toString());
      if (category) params.append('category', category);

      const response = await fetch(`/api/scores/${domain}/timeline?${params}`);
      
      if (!response.ok) {
        throw new Error(`Failed to fetch timeline data: ${response.statusText}`);
      }

      const data = await response.json();
      setTimelineData(data.timeline || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load timeline data');
      console.error('Error fetching timeline data:', err);
    } finally {
      setLoading(false);
    }
  };

  const prepareChartData = () => {
    if (!timelineData.length) return null;

    // Group data by category if showing multiple categories
    const categories = Array.from(new Set(timelineData.map(item => item.category)));
    
    const datasets = categories.map((cat, index) => {
      const categoryData = timelineData
        .filter(item => item.category === cat)
        .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

      const colors = [
        'rgb(59, 130, 246)', // Blue
        'rgb(16, 185, 129)', // Green  
        'rgb(245, 101, 101)', // Red
        'rgb(251, 191, 36)', // Yellow
        'rgb(139, 92, 246)', // Purple
        'rgb(236, 72, 153)', // Pink
      ];

      // Use actual data points only
      const chartData = categoryData.map(item => ({
        x: new Date(item.date),
        y: item.score
      }));

      return {
        label: cat,
        data: chartData,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59, 130, 246, 0.3)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointHoverRadius: 6,
        pointBackgroundColor: '#3b82f6',
        pointBorderColor: '#ffffff',
        pointBorderWidth: 2,
      };
    });

    return {
      datasets
    };
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false, // Hide legend since we show it in the header
      },
      tooltip: {
        mode: 'index' as const,
        intersect: false,
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: '#fff',
        bodyColor: '#fff',
        borderColor: '#3b82f6',
        borderWidth: 1,
        callbacks: {
          title: (context: any) => {
            return new Date(context[0].parsed.x).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
              year: 'numeric'
            });
          },
          label: (context: any) => {
            return `Score: ${context.parsed.y}/950`;
          }
        }
      }
    },
    scales: {
      x: {
        type: 'time' as const,
        time: {
          unit: 'day' as const,
          displayFormats: {
            day: 'MMM d',
            week: 'MMM d',
            month: 'MMM d'
          }
        },
        grid: {
          display: true,
          color: '#f1f5f9',
          drawBorder: false,
        },
        ticks: {
          source: 'data' as const,
          maxTicksLimit: 8,
          color: '#64748b',
          font: {
            size: 11
          },
          callback: function(value: any) {
            const date = new Date(value);
            return date.toLocaleDateString('en-US', { 
              month: 'short', 
              day: 'numeric' 
            });
          }
        },
        border: {
          display: false
        }
      },
      y: {
        beginAtZero: true,
        min: 0,
        max: 1000,
        grid: {
          display: true,
          color: '#f1f5f9',
          drawBorder: false,
        },
        ticks: {
          color: '#64748b',
          font: {
            size: 11
          },
          // Manually specify the exact tick values
          stepSize: null,
          count: 6,
          callback: function(value: any) {
            return value;
          }
        },
        // Force exact tick positions
        afterBuildTicks: (axis: any) => {
          axis.ticks = [
            { value: 0, label: '0' },
            { value: 200, label: '200' },
            { value: 400, label: '400' },
            { value: 600, label: '600' },
            { value: 800, label: '800' },
            { value: 950, label: '950' }
          ];
        },
        border: {
          display: false
        }
      }
    },
    interaction: {
      mode: 'nearest' as const,
      axis: 'x' as const,
      intersect: false
    },
    elements: {
      point: {
        radius: 4,
        hoverRadius: 6,
        backgroundColor: '#3b82f6',
        borderColor: '#ffffff',
        borderWidth: 2
      },
      line: {
        borderWidth: 2,
        tension: 0.1
      }
    }
  };

  if (loading) {
    return (
      <div className={`${isDarkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow p-6`}>
        <div className="animate-pulse">
          <div className={`h-4 ${isDarkMode ? 'bg-gray-600' : 'bg-gray-200'} rounded w-1/4 mb-4`}></div>
          <div className={`h-64 ${isDarkMode ? 'bg-gray-600' : 'bg-gray-200'} rounded`}></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`${isDarkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow p-6`}>
        <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2`}>{title}</h3>
        <div className="text-red-600 text-center py-8">
          <p>Error loading timeline data: {error}</p>
          <button 
            onClick={fetchTimelineData}
            className="mt-2 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!timelineData.length) {
    return (
      <div className={`${isDarkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow p-6`}>
        <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2`}>{title}</h3>
        <div className={`${isDarkMode ? 'text-gray-300' : 'text-gray-500'} text-center py-8`}>
          <p>No score data available</p>
        </div>
      </div>
    );
  }

  const chartData = prepareChartData();

  // Plugin to add gradient
  const gradientPlugin = {
    id: 'gradientPlugin',
    beforeDatasetsDraw: (chart: any) => {
      const { ctx, chartArea, data } = chart;
      
      data.datasets.forEach((dataset: any, index: number) => {
        if (dataset.fill && index === 0) {
          const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
          gradient.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
          gradient.addColorStop(0.3, 'rgba(59, 130, 246, 0.25)');
          gradient.addColorStop(0.7, 'rgba(59, 130, 246, 0.1)');
          gradient.addColorStop(1, 'rgba(59, 130, 246, 0.02)');
          dataset.backgroundColor = gradient;
        }
      });
    }
  };

  return (
    <div style={{
      background: isDarkMode ? 'var(--bg-secondary)' : 'white',
      borderRadius: '12px',
      padding: '1.5rem',
      boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
      border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e5e7eb'}`,
      marginBottom: '1rem'
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '1.5rem'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <i className="fas fa-chart-line" style={{ color: '#3b82f6' }}></i>
          <h4 style={{
            margin: 0,
            fontSize: '1.125rem',
            fontWeight: '600',
            color: isDarkMode ? 'var(--text-primary)' : '#1f2937'
          }}>
            Average vendor rating over time
          </h4>
        </div>
      </div>

      {/* Current Score Display */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '1rem',
        marginBottom: '1.5rem',
        padding: '1rem',
        backgroundColor: isDarkMode ? 'var(--bg-primary)' : '#f8fafc',
        borderRadius: '8px',
        border: `1px solid ${isDarkMode ? 'var(--border-color)' : '#e2e8f0'}`
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <div style={{
            width: '12px',
            height: '12px',
            backgroundColor: '#3b82f6',
            borderRadius: '2px'
          }}></div>
          <span style={{
            fontSize: '0.875rem',
            color: '#64748b',
            fontWeight: '500'
          }}>
            Average Vendor Rating
          </span>
        </div>
        <div style={{
          fontSize: '1.25rem',
          fontWeight: '600',
          color: '#1e293b'
        }}>
          {timelineData.length > 0 ? `${timelineData[timelineData.length - 1].score}` : 'N/A'}
        </div>
      </div>

      {/* Chart Container */}
      <div style={{ 
        height: '300px',
        marginBottom: '1rem'
      }}>
        {chartData && <Line data={chartData} options={chartOptions} plugins={[gradientPlugin]} />}
      </div>

      {/* Footer Info */}
      <div style={{
        fontSize: '0.75rem',
        color: '#64748b',
        textAlign: 'center'
      }}>
        Showing {timelineData.length} score entries over the past {months} months
      </div>
    </div>
  );
};

export default ScoreTimelineChart; 