import React from 'react';
import ReactDOM from 'react-dom/client';
import { DesignPreviewApp } from './DesignPreviewApp';
import './styles/tokens.css';
import './styles/components.css';
import './styles/enrichment.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <DesignPreviewApp />
  </React.StrictMode>
);
