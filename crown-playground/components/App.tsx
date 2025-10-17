import React, { useState } from 'react';
import { AeadPanel } from './AeadPanel';
import { BlockPanel } from './BlockPanel';
import { HashPanel } from './HashPanel';
import { Sidebar } from './Sidebar';
import { StreamPanel } from './StreamPanel';

export function App() {
  const [activeTab, setActiveTab] = useState('aead');

  const renderPanel = () => {
    switch (activeTab) {
      case 'aead':
        return <AeadPanel />;
      case 'block':
        return <BlockPanel />;
      case 'hash':
        return <HashPanel />;
      case 'stream':
        return <StreamPanel />;
      default:
        return <AeadPanel />;
    }
  };

  return (
    <div className="flex h-screen bg-white dark:bg-gray-900">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
      <div className="flex-1 overflow-auto">{renderPanel()}</div>
    </div>
  );
}
