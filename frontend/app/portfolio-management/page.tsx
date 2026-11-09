'use client';

import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Layout from '../../components/Layout';
import PortfolioManagement from '../../components/PortfolioManagement';
import { PermissionGate, usePermission } from '../../lib/rbac';

const PortfolioManagementPage: React.FC = () => {
  const router = useRouter();
  const canViewPortfolios = usePermission('view_portfolios');

  useEffect(() => {
    if (!canViewPortfolios) {
      router.replace('/');
    }
  }, [canViewPortfolios, router]);

  return (
    <Layout activeSection="portfolio-management">
      <PermissionGate
        permission="view_portfolios"
        fallback={
          <div className="portfolio-page-container">
            <div className="portfolio-main-wrapper">
              <div className="portfolio-page-header">
                <h1 className="portfolio-page-title">Portfolios</h1>
              </div>
              <p>You do not have permission to view portfolios.</p>
            </div>
          </div>
        }
      >
        <div className="portfolio-page-container">
          <div className="portfolio-main-wrapper">
            <div className="portfolio-page-header">
              <h1 className="portfolio-page-title">Portfolios</h1>
              <p className="portfolio-page-subtitle">
                Monitor and analyze security scores across different vendor portfolios
              </p>
            </div>
            <PortfolioManagement />
          </div>
        </div>
      </PermissionGate>
    </Layout>
  );
};

export default PortfolioManagementPage;
