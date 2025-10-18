'use client';

import { AppSidebar, menuItems } from '@/components/AppSidebar';
import './global.css';
import { usePathname } from 'next/navigation';
import { Suspense } from 'react';
import { ThemeToggle } from '@/components/ThemeToggle';
import {
  Sidebar,
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  let label = '';
  for (const i of menuItems) {
    if (pathname == `/${i.id}/`) {
      label = i.label;
    }
  }

  return (
    <html lang="en">
      <head>
        <title>Crown Playground</title>
      </head>
      <body>
        <SidebarProvider defaultOpen={true}>
          <AppSidebar />
          <SidebarInset>
            <header className="flex px-4 h-16 shrink-0 items-center border-b justify-between">
              <div className="flex items-center gap-2">
                <SidebarTrigger className="-ml-1" />
                <h1 className="text-lg font-semibold">{label}</h1>
              </div>
              <ThemeToggle />
            </header>
            <div className="flex-1 overflow-auto bg-background text-foreground p-4">
              <Suspense>{children}</Suspense>
            </div>
          </SidebarInset>
        </SidebarProvider>
      </body>
    </html>
  );
}
