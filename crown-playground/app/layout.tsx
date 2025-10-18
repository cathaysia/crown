import './global.css';
import { SidebarProvider } from '@/components/ui/sidebar';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <title>Crown Playground</title>
      </head>
      <body>
        <SidebarProvider defaultOpen={true}>{children}</SidebarProvider>
      </body>
    </html>
  );
}
