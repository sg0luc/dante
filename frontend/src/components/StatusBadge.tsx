import React from "react";
import { AlertState, RuleState, SilenceState } from "../types";

interface Props {
  state: RuleState | AlertState | SilenceState | string;
  type?: "rule" | "alert" | "silence";
}

export const StatusBadge: React.FC<Props> = ({ state }) => {
  const normalized = state.toLowerCase();

  let badgeClass = "badge-normal";
  let label = state;

  switch (normalized) {
    case "firing":
      badgeClass = "badge-firing";
      label = "Disparando";
      break;
    case "active":
      badgeClass = "badge-firing";
      label = "Ativo";
      break;
    case "pending":
      badgeClass = "badge-pending";
      label = "Pendente";
      break;
    case "recovering":
      badgeClass = "badge-normal";
      label = "Recuperando";
      break;
    case "normal":
      badgeClass = "badge-normal";
      label = "Normal";
      break;
    case "paused":
      badgeClass = "badge-paused";
      label = "Pausado";
      break;
    case "silenced":
    case "suppressed":
      badgeClass = "badge-silenced";
      label = "Silenciado";
      break;
    case "expired":
      badgeClass = "badge-paused";
      label = "Expirado";
      break;
    case "error":
      badgeClass = "badge-firing";
      label = "Erro";
      break;
    case "nodata":
      badgeClass = "badge-pending";
      label = "Sem Dados";
      break;
    default:
      badgeClass = "badge-paused";
      label = state;
  }

  return <span className={`badge ${badgeClass}`}>{label}</span>;
};

