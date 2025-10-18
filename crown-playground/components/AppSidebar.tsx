'use client';

import { Crown, Hash, Lock, Shield, Zap } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar';

export const menuItems = [
  { id: 'aead', label: 'AEAD Cipher', icon: Shield },
  { id: 'block', label: 'Block Cipher', icon: Lock },
  { id: 'hash', label: 'Hash', icon: Hash },
  { id: 'stream', label: 'Stream Cipher', icon: Zap },
];

export function AppSidebar() {
  const pathname = usePathname();

  return (
    <Sidebar collapsible="icon" variant="floating">
      <SidebarHeader className="p-4">
        <div className="flex flex-col items-center gap-3">
          <div className="group-data-[collapsible=icon]:hidden w-full">
            <div className="flex flex-col items-center gap-2">
              <Link
                href="https://github.com/cathaysia/crown"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-center w-16 h-16 rounded-full bg-gradient-to-br from-yellow-400 to-yellow-600 hover:from-yellow-500 hover:to-yellow-700 transition-all duration-300 shadow-lg hover:shadow-xl transform hover:scale-105"
              >
                <Crown className="w-8 h-8 text-white" />
              </Link>
              <div className="text-center">
                <h1 className="text-lg font-bold text-sidebar-foreground">
                  Crown Crypto
                </h1>
                <p className="text-xs text-sidebar-foreground/70">
                  Cryptography Playground
                </p>
              </div>
            </div>
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Cipher</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {menuItems.map(item => {
                const isActive = pathname == `/${item.id}/`;
                return (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton asChild isActive={isActive}>
                      <Link href={`/${item.id}`}>
                        <item.icon className="w-4 h-4" />
                        <span>{item.label}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  );
}
