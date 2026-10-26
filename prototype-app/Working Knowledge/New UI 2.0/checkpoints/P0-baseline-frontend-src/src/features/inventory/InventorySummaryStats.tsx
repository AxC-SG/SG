import React from 'react';
import type { InventoryViewKey } from './types';

type Props = {
  selectedView: InventoryViewKey;
  componentTotalItems: number;
  retiredCount: number;
  assetCount: number;
  needsReviewCount: number;
  onRetiredClick: () => void;
};

export function InventorySummaryStats({
  selectedView,
  componentTotalItems,
  retiredCount,
  assetCount,
  needsReviewCount,
  onRetiredClick
}: Props) {
  return (
    <div className="fpl-widgets">
      <div className="fpl-widget">
        <div className="fpl-widget-title">Inventory Records</div>
        <div className="fpl-widget-body">
          <div className="fpl-stat-num">{componentTotalItems.toLocaleString()}</div>
          {retiredCount > 0 && (
            <button type="button" className="btn-link fpl-stat-subcount" onClick={onRetiredClick}>
              {retiredCount.toLocaleString()} retired
            </button>
          )}
        </div>
      </div>

      <div className="fpl-widget">
        <div className="fpl-widget-title">Assets Represented</div>
        <div className="fpl-widget-body">
          <div className="fpl-stat-num">{assetCount.toLocaleString()}</div>
        </div>
      </div>

      {selectedView === 'hosts' && (
        <div className="fpl-widget">
          <div className="fpl-widget-title">Rows Needing Review</div>
          <div className="fpl-widget-body">
            <div className="fpl-stat-num">{needsReviewCount.toLocaleString()}</div>
          </div>
        </div>
      )}
    </div>
  );
}
