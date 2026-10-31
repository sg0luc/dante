import React from "react";
import { DeployStatus } from "../types";

/**
 * Badge do estágio de deploy de uma regra de detecção.
 *
 * O estágio é derivado do Contact Point amarrado à regra (backend
 * `contact_points.derive_deploy_status`):
 *   prod            -> Ativa
 *   dev / stg       -> Homologação
 *   isPaused        -> Pausada (independente do Contact Point)
 *   sem Contact Point -> Sem Contact Point (ninguém recebe o alerta)
 */
const LABELS: Record<DeployStatus, string> = {
  active: "Ativa",
  homolog: "Homologação",
  paused: "Pausada",
  unassigned: "Sem Contact Point",
};

const CLASSES: Record<DeployStatus, string> = {
  active: "badge badge-normal",
  homolog: "badge badge-homolog",
  paused: "badge badge-paused",
  unassigned: "badge badge-unassigned",
};

interface Props {
  status: DeployStatus;
  /** Contact Point de origem, exibido como tooltip/legenda. */
  contactPoint?: string | null;
  showContactPoint?: boolean;
  /** Torna o badge clicável (ex.: abrir pop-up de volume/histórico em Homologação). */
  onClick?: () => void;
  interactiveTitle?: string;
}

export const DeployStatusBadge: React.FC<Props> = ({
  status,
  contactPoint,
  showContactPoint = false,
  onClick,
  interactiveTitle,
}) => {
  const defaultTitle = `Contact Point: ${contactPoint || "nenhum"}`;
  const title = interactiveTitle || (onClick ? `${defaultTitle} — Clique para ver volume e histórico de alertas` : defaultTitle);
  const badgeClass = `${CLASSES[status] || "badge badge-paused"}${
    onClick ? " badge-homolog-clickable" : ""
  }`;

  return (
    <span style={{ display: "inline-flex", flexDirection: "column", gap: "2px" }}>
      {onClick ? (
        <button
          type="button"
          onClick={onClick}
          className={badgeClass}
          title={title}
          style={{ whiteSpace: "nowrap" }}
        >
          <span>{LABELS[status] || status}</span>
        </button>
      ) : (
        <span
          className={badgeClass}
          title={title}
          style={{ whiteSpace: "nowrap" }}
        >
          {LABELS[status] || status}
        </span>
      )}
      {showContactPoint && (
        <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
          CP: {contactPoint || "—"}
        </span>
      )}
    </span>
  );
};
