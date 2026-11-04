import React, { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { DanteLogo } from "./components/DanteLogo";
import { Sidebar } from "./components/Sidebar";
import { SystemUpdateModal } from "./components/SystemUpdateModal";
import { TopHeader } from "./components/TopHeader";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { api } from "./api";
import { AlertsPage } from "./pages/AlertsPage";
import { ApiKeysPage } from "./pages/ApiKeysPage";
import { BaselinePrefixPage } from "./pages/BaselinePrefixPage";
import { CuradoriaPage } from "./pages/CuradoriaPage";
import { GlobalMatrixPage } from "./pages/GlobalMatrixPage";
import { HomologationPage } from "./pages/HomologationPage";
import { LoginPage } from "./pages/LoginPage";
import { LokiLabPage } from "./pages/LokiLabPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RulesPage } from "./pages/RulesPage";
import { SilencesPage } from "./pages/SilencesPage";
import { TechnologiesPage } from "./pages/TechnologiesPage";
import { TenantsPage } from "./pages/TenantsPage";
import { SystemUpdatesPage } from "./pages/SystemUpdatesPage";
import { UsersPage } from "./pages/UsersPage";
import { PortalConfig } from "./types";

const ProtectedLayout: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { user, loading } = useAuth();
  const [config, setConfig] = useState<PortalConfig | null>(null);
  const [alertCount, setAlertCount] = useState<number>(0);
  const [silenceCount, setSilenceCount] = useState<number>(0);
  const [version, setVersion] = useState<string>("v1.0.0");
  const [isUpdateModalOpen, setIsUpdateModalOpen] = useState<boolean>(false);
  const [updateAvailable, setUpdateAvailable] = useState<boolean>(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem("dante_sidebar_collapsed") === "true";
    } catch {
      return false;
    }
  });

  const toggleSidebar = () => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("dante_sidebar_collapsed", String(next));
      } catch {}
      return next;
    });
  };

  useEffect(() => {
    const timer = setTimeout(() => {
      window.dispatchEvent(new Event("resize"));
    }, 220);
    return () => clearTimeout(timer);
  }, [sidebarCollapsed]);

  useEffect(() => {
    if (user) {
      api.getConfig().then(setConfig).catch(() => {});
      api
        .getRules()
        .then((rules) => {
          const firing = rules.filter(
            (r) => r.state?.toLowerCase() === "firing" || r.state?.toLowerCase() === "alerting"
          );
          setAlertCount(firing.length);
        })
        .catch(() => {});
      api
        .getSilences()
        .then((s) => {
          const active = s.filter((item) => item.state === "active");
          setSilenceCount(active.length);
        })
        .catch(() => {});
      api
        .getVersion()
        .then((v) => {
          if (v?.current_version) setVersion(v.current_version);
          if (v?.update_available) setUpdateAvailable(true);
        })
        .catch(() => {});
    }
  }, [user]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background text-on-surface-variant font-body-md">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-surface-container-high border border-outline-variant/50 flex items-center justify-center shadow-[0_0_16px_rgba(225,29,72,0.35)] animate-pulse">
            <DanteLogo size={24} glow={false} />
          </div>
          <span>Carregando portal de segurança...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="min-h-screen bg-background text-on-surface flex">
      <Sidebar
        config={config}
        alertCount={alertCount}
        silenceCount={silenceCount}
        version={version}
        updateAvailable={updateAvailable}
        onOpenUpdateModal={() => setIsUpdateModalOpen(true)}
        collapsed={sidebarCollapsed}
        onToggleCollapse={toggleSidebar}
      />
      <SystemUpdateModal
        isOpen={isUpdateModalOpen}
        onClose={() => setIsUpdateModalOpen(false)}
        onVersionUpdated={(newV) => {
          setVersion(newV);
          setUpdateAvailable(false);
        }}
      />
      <div
        className={`${
          sidebarCollapsed ? "pl-16" : "pl-64"
        } flex-1 flex flex-col min-w-0 transition-all duration-200`}
      >
        <TopHeader
          config={config}
          alertCount={alertCount}
          sidebarCollapsed={sidebarCollapsed}
        />
        <main className="w-full pt-14 px-margin bg-background min-h-screen overflow-x-hidden">
          <div className="py-4 w-full">{children}</div>
        </main>
      </div>
    </div>
  );
};

const PublicLoginRoute: React.FC = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return null;
  }

  if (user) {
    return <Navigate to="/" replace />;
  }

  return <LoginPage />;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<PublicLoginRoute />} />
          <Route
            path="/"
            element={
              <ProtectedLayout>
                <OverviewPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/rules"
            element={
              <ProtectedLayout>
                <RulesPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/curadoria"
            element={
              <ProtectedLayout>
                <CuradoriaPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/homologacao"
            element={
              <ProtectedLayout>
                <HomologationPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/baseline"
            element={
              <ProtectedLayout>
                <GlobalMatrixPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/global-rules"
            element={
              <ProtectedLayout>
                <GlobalMatrixPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/tenants"
            element={
              <ProtectedLayout>
                <TenantsPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/api-keys"
            element={
              <ProtectedLayout>
                <ApiKeysPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/baseline-prefix"
            element={
              <ProtectedLayout>
                <BaselinePrefixPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/technologies"
            element={
              <ProtectedLayout>
                <TechnologiesPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/loki"
            element={
              <ProtectedLayout>
                <LokiLabPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/alerts"
            element={
              <ProtectedLayout>
                <AlertsPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/silences"
            element={
              <ProtectedLayout>
                <SilencesPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/users"
            element={
              <ProtectedLayout>
                <UsersPage />
              </ProtectedLayout>
            }
          />
          <Route
            path="/system"
            element={
              <ProtectedLayout>
                <SystemUpdatesPage />
              </ProtectedLayout>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};