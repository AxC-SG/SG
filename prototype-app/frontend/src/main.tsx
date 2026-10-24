import React from 'react';
import ReactDOM from 'react-dom/client';
import * as Sentry from '@sentry/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { createQueryClient } from './lib/queryClient';
import { privateTelemetryOptions } from './lib/telemetryPrivacy';
import { applyUiVersion } from './lib/uiVersion';

Sentry.init(privateTelemetryOptions(import.meta.env.VITE_SENTRY_DSN, import.meta.env.MODE));
applyUiVersion(document.documentElement, import.meta.env.VITE_UI_VERSION);

const queryClient = createQueryClient();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);
