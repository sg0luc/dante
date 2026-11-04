import React from "react";
import { Modal } from "./Modal";
import { AISettingsForm } from "./AISettingsForm";

interface AISettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSaved?: () => void;
}

export const AISettingsModal: React.FC<AISettingsModalProps> = ({
  isOpen,
  onClose,
  onSaved,
}) => {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title="API Keys — Inteligência Artificial" maxWidth="780px">
      <AISettingsForm
        onCancel={onClose}
        onSaved={() => {
          if (onSaved) onSaved();
          onClose();
        }}
      />
    </Modal>
  );
};
