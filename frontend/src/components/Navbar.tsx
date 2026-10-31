import React, { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { api } from "../api";
import { DanteLogo } from "./DanteLogo";
import { useAuth } from "../context/AuthContext";
import { PortalConfig } from "../types";

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [config, setConfig] = useState<PortalConfig | null>(null);

  useEffect(() => {
    api.getConfig().then(setConfig).catch(() => {});
  }, []);

  return (
    <nav className="navbar">
      <div style={{ display: "flex", alignItems: "center", gap: "32px" }}>
        <Link to="/" className="navbar-brand" title="D.A.N.T.E. - Detection & Alerting Navigator for Threat Engineering">
          <div className="brand-icon">
            <DanteLogo size={22} glow />
          </div>
          <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.1 }}>
            <span style={{ fontWeight: 800, letterSpacing: "0.08em", fontSize: "1.05rem", color: "#ffffff" }}>
              D.A.N.T.E.
            </span>
            <span style={{ fontSize: "0.58rem", color: "var(--text-muted)", letterSpacing: "0.05em", textTransform: "uppercase", fontWeight: 600 }}>
              Threat Engineering
            </span>
          </div>
        </Link>

        <ul className="navbar-links">
          <li>
            <Link
              to="/"
              className={`nav-link ${location.pathname === "/" ? "active" : ""}`}
            >
              Visão Geral
            </Link>
          </li>
          <li>
            <Link
              to="/rules"
              className={`nav-link ${location.pathname === "/rules" ? "active" : ""}`}
            >
              Regras
            </Link>
          </li>
          <li>
            <Link
              to="/curadoria"
              className={`nav-link ${location.pathname.startsWith("/curadoria") ? "active" : ""}`}
            >
              Curadoria
            </Link>
          </li>
          <li>
            <Link
              to="/homologacao"
              className={`nav-link ${location.pathname.startsWith("/homologacao") ? "active" : ""}`}
            >
              Homologação
            </Link>
          </li>
          <li>
            <Link
              to="/baseline"
              className={`nav-link ${location.pathname.startsWith("/baseline") || location.pathname.startsWith("/global-rules") ? "active" : ""}`}
            >
              Controle de Baseline
            </Link>
          </li>
          <li>
            <Link
              to="/technologies"
              className={`nav-link ${location.pathname.startsWith("/technologies") ? "active" : ""}`}
            >
              Tecnologias
            </Link>
          </li>
          <li>
            <Link
              to="/tenants"
              className={`nav-link ${location.pathname.startsWith("/tenants") ? "active" : ""}`}
            >
              Tenants
            </Link>
          </li>
          <li>
            <Link
              to="/loki"
              className={`nav-link ${location.pathname.startsWith("/loki") ? "active" : ""}`}
            >
              Logs Sintéticos
            </Link>
          </li>
          <li>
            <Link
              to="/alerts"
              className={`nav-link ${location.pathname.startsWith("/alerts") ? "active" : ""}`}
            >
              Alertas
            </Link>
          </li>
          <li>
            <Link
              to="/silences"
              className={`nav-link ${location.pathname.startsWith("/silences") ? "active" : ""}`}
            >
              Silences
            </Link>
          </li>
        </ul>
      </div>

      <div className="navbar-actions">
        {config?.grafana_public_url && (
          <a
            href={config.grafana_public_url}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-secondary btn-sm"
            title="Abrir a interface oficial do Grafana"
          >
            Abrir Grafana ↗
          </a>
        )}

        {user && (
          <div className="user-badge">
            <span className="user-avatar"></span>
            <span>{user.username}</span>
          </div>
        )}

        <button
          onClick={logout}
          className="btn btn-secondary btn-sm"
          title="Encerrar sessão"
        >
          Sair
        </button>
      </div>
    </nav>
  );
};

