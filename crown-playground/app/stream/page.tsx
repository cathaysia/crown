import { AppSidebar } from '@/components/AppSidebar';
import { StreamPanel } from '@/components/StreamPanel';
import { SidebarInset, SidebarTrigger } from '@/components/ui/sidebar';

export default function StreamPage() {
  return (
    <>
      <AppSidebar activeTab="stream" />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1" />
          <h1 className="text-lg font-semibold">Stream Cipher</h1>
        </header>
        <div className="flex-1 overflow-auto bg-background text-foreground p-4">
          <StreamPanel />
        </div>
      </SidebarInset>
    </>
  );
}
