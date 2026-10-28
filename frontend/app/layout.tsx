import type { Metadata, Viewport } from 'next';
import { Inter } from 'next/font/google';
import { headers } from 'next/headers';
import '../styles/globals.css';
import '../styles/theme-modern.css';
import { SessionProvider } from '../components/SessionProvider';
import { resolveRole } from '../lib/auth-config';
import { loadUserPermissions } from '../lib/load-user-permissions';
import type { UserInfo } from '../lib/user-context';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Vendiant Security Dashboard',
  description: 'Comprehensive vendor security monitoring and assessment platform',
  keywords: 'security, vendor management, vulnerability assessment, compliance',
  authors: [{ name: 'Vendiant Security Team' }],
  icons: {
    icon: '/shield.png',
    shortcut: '/shield.png',
    apple: '/shield.png',
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const headersList = await headers();

  const email = headersList.get('x-user-email') ?? '';
  const name = headersList.get('x-user-name') ?? undefined;
  const sub = headersList.get('x-user-id') ?? undefined;
  const groupsHeader = headersList.get('x-user-groups') ?? '';
  const groups = groupsHeader ? groupsHeader.split(',').filter(Boolean) : [];
  const role = resolveRole(groups);

  const loaded = await loadUserPermissions({
    email,
    role,
    userId: sub,
    name,
  });

  const user: UserInfo = {
    email,
    name,
    sub,
    groups,
    role,
    permissions: loaded.permissions,
    permissionsFromAssignment: loaded.hasAssignment,
  };

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"
          rel="stylesheet"
        />
      </head>
      <body className={inter.className} suppressHydrationWarning>
        {/*
          Applies the persisted theme and sidebar width before first paint.
          Without this, both are only restored in a mount effect, so every
          route change rendered the light theme and a full-width sidebar for
          a frame and then corrected itself — a visible flash.
          Must stay a blocking inline script at the top of <body>: it needs
          document.body (the theme class is read from there by chart
          components) and it must run before the sidebar is painted.
        */}
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{
if(localStorage.getItem('theme')==='dark'){document.body.classList.add('dark-mode');}
document.documentElement.setAttribute('data-sidebar',localStorage.getItem('sidebarCollapsed')==='true'?'collapsed':'expanded');
}catch(e){}})();`,
          }}
        />
        <SessionProvider user={user}>
          {children}
        </SessionProvider>
      </body>
    </html>
  );
}
