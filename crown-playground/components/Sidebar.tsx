import { Hash, Lock, Shield, Zap } from 'lucide-react';
import React from 'react';
import { cn } from '@/lib/utils';
import { ThemeToggle } from './ThemeToggle';

interface SidebarProps {
  activeTab: string;
  onTabChange?: (tab: string) => void;
}

const menuItems = [
  { id: 'aead', label: 'AEAD Cipher', icon: Shield },
  { id: 'block', label: 'Block Cipher', icon: Lock },
  { id: 'hash', label: 'Hash', icon: Hash },
  { id: 'stream', label: 'Stream Cipher', icon: Zap },
];

export function Sidebar({ activeTab, onTabChange }: SidebarProps) {
  const handleTabChange = (tab: string) => {
    if (onTabChange) {
      onTabChange(tab);
    } else {
      window.location.href = `/${tab}`;
    }
  };
  return (
    <div className="w-64 bg-muted border-r border-border h-full">
      <div className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Crown Crypto</h1>
            <p className="text-sm text-muted-foreground mt-2">
              Cryptography Playground
            </p>
          </div>
        </div>
      </div>

      <nav className="mt-8">
        {menuItems.map(item => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => handleTabChange(item.id)}
              className={cn(
                'w-full flex items-center px-6 py-3 text-left hover:bg-accent hover:text-accent-foreground transition-colors text-foreground',
                activeTab === item.id &&
                  'bg-primary/10 border-r-2 border-primary text-primary',
              )}
            >
              <Icon className="w-5 h-5 mr-3" />
              <span className="font-medium">{item.label}</span>
            </button>
          );
        })}
      </nav>
    </div>
  );
}
