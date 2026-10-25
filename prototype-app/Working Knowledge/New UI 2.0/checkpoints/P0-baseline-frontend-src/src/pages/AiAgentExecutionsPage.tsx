import { Navigate } from 'react-router-dom';

/** Legacy bookmarks return to the supported static inventory. */
export function AiAgentExecutionsPage() {
  return <Navigate to="/inventory/ai" replace />;
}
