import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";

export const UsersPage: React.FC = () => {
  const { user } = useAuth();
  const [searchTerm, setSearchTerm] = useState("");

  const usersList = [
    {
      id: "u1",
      username: user?.username || "hunter",
      role: "Security Engineer / SecOps L3",
      level: "ADMIN",
      lastLogin: "Agora (Sessão Ativa)",
      status: "Ativo",
    },
    {
      id: "u2",
      username: "soc_analyst_t2",
      role: "SOC Incident Responder Tier 2",
      level: "OPERATOR",
      lastLogin: "Há 2 horas",
      status: "Ativo",
    },
    {
      id: "u3",
      username: "detection_dev",
      role: "Detection Engineer",
      level: "EDITOR",
      lastLogin: "Ontem às 18:40",
      status: "Ativo",
    },
    {
      id: "u4",
      username: "auditor_sec",
      role: "Compliance & Security Auditor",
      level: "VIEWER",
      lastLogin: "Há 4 dias",
      status: "Ativo",
    },
  ];

  const filtered = usersList.filter(
    (u) =>
      u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
      u.role.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="flex flex-col w-full space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex flex-col space-y-1.5">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight">
              Usuários &amp; Permissões
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-surface-container-high text-secondary text-code-sm font-code-sm border border-secondary/30">
              <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
              RBAC &amp; Controle de Acesso
            </span>
          </div>
          <p className="font-body-sm text-body-sm text-on-surface-variant max-w-2xl">
            Gerenciamento de credenciais locais, tokens de API e níveis de autorização do portal D.A.N.T.E.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface text-body-sm font-body-sm border border-outline-variant/30 transition-all shadow-sm active:scale-95"
          >
            <span className="material-symbols-outlined text-[18px]">key</span>
            <span>Regerar CSRF</span>
          </button>
          <button
            type="button"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary-container text-on-primary-container text-body-sm font-body-sm font-semibold shadow-[0_0_12px_rgba(225,29,72,0.3)] hover:opacity-90 transition-all active:scale-95"
          >
            <span className="material-symbols-outlined text-[18px]">person_add</span>
            <span>Novo Usuário</span>
          </button>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex items-center gap-3 p-3 rounded-xl bg-surface-container-low border border-outline-variant/30">
        <div className="relative flex-1">
          <span className="material-symbols-outlined absolute left-3 top-2 text-[18px] text-outline">
            search
          </span>
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filtrar por nome de usuário, papel ou nível de permissão..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface text-body-sm placeholder:text-outline focus:outline-none focus:border-secondary"
          />
        </div>
        <span className="text-code-sm font-code-sm text-outline px-2">
          {filtered.length} usuário(s)
        </span>
      </div>

      {/* Users Table */}
      <div className="rounded-xl bg-surface-container-lowest border border-outline-variant/30 overflow-hidden shadow-sm">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-surface-container-low text-outline font-label-uppercase text-label-uppercase uppercase tracking-wider border-b border-outline-variant/30">
              <th className="py-2.5 px-4">Usuário</th>
              <th className="py-2.5 px-4">Função / Papel</th>
              <th className="py-2.5 px-4">Nível RBAC</th>
              <th className="py-2.5 px-4">Último Acesso</th>
              <th className="py-2.5 px-4">Status</th>
              <th className="py-2.5 px-4 text-right">Ações</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-outline-variant/20 font-body-sm text-body-sm text-on-surface">
            {filtered.map((u) => (
              <tr
                key={u.id}
                className="hover:bg-surface-container-low/60 transition-colors group"
              >
                <td className="py-3 px-4 font-semibold flex items-center gap-2">
                  <div className="w-7 h-7 rounded-full bg-primary-container flex items-center justify-center text-on-primary-container text-code-sm font-mono">
                    {u.username.charAt(0).toUpperCase()}
                  </div>
                  <span>{u.username}</span>
                </td>
                <td className="py-3 px-4 text-on-surface-variant">{u.role}</td>
                <td className="py-3 px-4">
                  <span
                    className={`px-2 py-0.5 rounded-full font-code-sm text-code-sm font-semibold border ${
                      u.level === "ADMIN"
                        ? "bg-primary-container/20 text-primary border-primary/30"
                        : u.level === "OPERATOR"
                        ? "bg-secondary-container/20 text-secondary border-secondary/30"
                        : "bg-surface-container-high text-on-surface border-outline-variant/30"
                    }`}
                  >
                    {u.level}
                  </span>
                </td>
                <td className="py-3 px-4 text-outline font-mono text-code-sm">
                  {u.lastLogin}
                </td>
                <td className="py-3 px-4">
                  <span className="inline-flex items-center gap-1.5 text-tertiary font-code-sm text-code-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
                    {u.status}
                  </span>
                </td>
                <td className="py-3 px-4 text-right">
                  <button
                    type="button"
                    className="p-1 rounded hover:bg-surface-container-high text-outline hover:text-on-surface transition-colors"
                    title="Editar permissões"
                  >
                    <span className="material-symbols-outlined text-[18px]">tune</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

