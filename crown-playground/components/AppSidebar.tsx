'use client';

import { Crown, Hash, Lock, Shield, Zap } from 'lucide-react';
import Link from 'next/link';
import React from 'react';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarTrigger,
} from '@/components/ui/sidebar';
import { ThemeToggle } from './ThemeToggle';

interface AppSidebarProps {
  activeTab: string;
}

const menuItems = [
  { id: 'aead', label: 'AEAD Cipher', icon: Shield },
  { id: 'block', label: 'Block Cipher', icon: Lock },
  { id: 'hash', label: 'Hash', icon: Hash },
  { id: 'stream', label: 'Stream Cipher', icon: Zap },
];

export function AppSidebar({ activeTab }: AppSidebarProps) {
  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="p-4">
        <div className="flex items-center gap-2">
          <div className="group-data-[collapsible=icon]:hidden">
            <h1 className="text-xl font-bold text-sidebar-foreground">
              Crown Crypto
            </h1>
            <p className="text-xs text-sidebar-foreground/70 mt-1">
              Cryptography Playground
            </p>
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <div className="px-2">
          <div className="flex h-8 shrink-0 items-center rounded-md px-2 text-xs font-medium text-sidebar-foreground/70 group-data-[collapsible=icon]:hidden">
            Cryptographic Functions
          </div>
          <SidebarMenu>
            {menuItems.map(item => {
              const Icon = item.icon;
              return (
                <SidebarMenuItem key={item.id}>
                  <SidebarMenuButton asChild isActive={activeTab === item.id}>
                    <Link href={`/${item.id}`}>
                      <Icon className="w-4 h-4" />
                      <span>{item.label}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              );
            })}
          </SidebarMenu>
        </div>
      </SidebarContent>

      <SidebarFooter className="p-4">
        <div className="flex justify-center">
          <ThemeToggle />
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
