import React, { useEffect } from "react";

export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string | React.ReactNode;
  children: React.ReactNode;
  /** Largura máxima opcional do diálogo (ex.: "980px" ou "1560px"); padrão do CSS é 640px. */
  maxWidth?: string;
  /** Largura opcional do diálogo (ex.: "96vw" ou "100%") */
  width?: string;
  /** Classes adicionais para estilizar o container do modal */
  className?: string;
  /** Estilos inline adicionais para o container do modal */
  style?: React.CSSProperties;
}

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  maxWidth,
  width,
  className,
  style,
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const contentStyle: React.CSSProperties = {
    ...(maxWidth ? { maxWidth } : {}),
    ...(width ? { width } : {}),
    ...style,
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className={`modal-content ${className || ""}`}
        style={contentStyle}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div className="modal-header">
          {typeof title === "string" ? (
            <h3 className="modal-title">{title}</h3>
          ) : (
            title
          )}
          <button
            className="modal-close"
            onClick={onClose}
            aria-label="Fechar modal"
          >
            &times;
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
};
