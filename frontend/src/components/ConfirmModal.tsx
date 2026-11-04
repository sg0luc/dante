import React from "react";
import { Modal } from "./Modal";

export interface ConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: "danger" | "warning" | "primary";
  isLoading?: boolean;
}

export const ConfirmModal: React.FC<ConfirmModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = "Confirmar",
  cancelLabel = "Cancelar",
  variant = "warning",
  isLoading = false,
}) => {
  if (!isOpen) return null;

  const isDanger = variant === "danger";
  const isWarning = variant === "warning";

  const bannerBg = isDanger
    ? "rgba(239, 68, 68, 0.1)"
    : isWarning
    ? "rgba(245, 158, 11, 0.1)"
    : "rgba(225, 29, 72, 0.1)";

  const bannerBorder = isDanger
    ? "rgba(239, 68, 68, 0.25)"
    : isWarning
    ? "rgba(245, 158, 11, 0.25)"
    : "rgba(225, 29, 72, 0.25)";

  const bannerColor = isDanger
    ? "#fb7185"
    : isWarning
    ? "#fbbf24"
    : "#f43f5e";

  const confirmBtnClass = isDanger
    ? "btn-danger"
    : isWarning
    ? "btn btn-secondary"
    : "btn-primary";

  return (
    <Modal isOpen={isOpen} onClose={isLoading ? () => {} : onClose} title={title}>
      <div>
        <div
          style={{
            backgroundColor: bannerBg,
            border: `1px solid ${bannerBorder}`,
            padding: "12px 14px",
            borderRadius: "8px",
            color: bannerColor,
            fontSize: "0.85rem",
            marginBottom: "16px",
            display: "flex",
            alignItems: "flex-start",
            gap: "8px",
          }}
        >
          <div style={{ flex: 1, lineHeight: 1.45 }}>
            {message}
          </div>
        </div>

        <div className="modal-footer" style={{ padding: "12px 0 0 0", marginTop: "16px" }}>
          <button
            type="button"
            onClick={onClose}
            className="btn btn-secondary"
            disabled={isLoading}
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={`btn ${confirmBtnClass}`}
            disabled={isLoading}
            style={
              isWarning
                ? {
                    borderColor: "rgba(245, 158, 11, 0.4)",
                    color: "#fbbf24",
                    backgroundColor: "rgba(245, 158, 11, 0.15)",
                  }
                : undefined
            }
          >
            {isLoading ? "Processando..." : confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
};
