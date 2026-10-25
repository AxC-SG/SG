import React from 'react';
import { HostAssetDetailPage } from '../../pages/HostAssetDetailPage';

type Props = {
  assetId: string | null;
  onClose: () => void;
};

export function HostInventoryDetailModal({ assetId, onClose }: Props) {
  if (!assetId) {
    return null;
  }

  return (
    <div
      className="modal-overlay"
      onClick={onClose}
    >
      <div
        className="modal-panel modal-panel-wide"
        onClick={(event) => event.stopPropagation()}
      >
        <HostAssetDetailPage
          assetId={assetId}
          onClose={onClose}
        />
      </div>
    </div>
  );
}
