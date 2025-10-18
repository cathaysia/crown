import { Suspense } from 'react';
import { AppSidebar } from '@/components/AppSidebar';
import { HashPanel } from '@/components/HashPanel';
import { SidebarInset, SidebarTrigger } from '@/components/ui/sidebar';

export default function HashPage() {
  return (
    <>
      <AppSidebar activeTab="hash" />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1" />
          <h1 className="text-lg font-semibold">Hash</h1>
        </header>
        <div className="flex-1 overflow-auto bg-background text-foreground p-4">
          <Suspense>
            <HashPanel />
          </Suspense>
        </div>
      </SidebarInset>
    </>
  );
}
