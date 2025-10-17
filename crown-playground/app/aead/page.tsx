import { AeadPanel } from '@/components/AeadPanel';
import { AppSidebar } from '@/components/AppSidebar';
import { SidebarInset, SidebarTrigger } from '@/components/ui/sidebar';

export default function AeadPage() {
  return (
    <>
      <AppSidebar activeTab="aead" />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1" />
          <h1 className="text-lg font-semibold">AEAD Cipher</h1>
        </header>
        <div className="flex-1 overflow-auto bg-background text-foreground p-4">
          <AeadPanel />
        </div>
      </SidebarInset>
    </>
  );
}
