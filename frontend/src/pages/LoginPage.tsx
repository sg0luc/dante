import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { DanteLogo } from "../components/DanteLogo";

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(username, password);
      navigate("/");
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Erro de autenticação. Verifique suas credenciais de operador.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background text-on-surface flex flex-col justify-between selection:bg-primary-container selection:text-on-primary-container relative overflow-hidden">
      {/* Dynamic Background Effects: Fine Grid & Radial Threat Glow */}
      <div
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: `linear-gradient(to right, #232733 1px, transparent 1px),
                            linear-gradient(to bottom, #232733 1px, transparent 1px)`,
          backgroundSize: "40px 40px",
          maskImage: "radial-gradient(ellipse 65% 55% at 50% 50%, #000 40%, transparent 100%)",
          WebkitMaskImage: "radial-gradient(ellipse 65% 55% at 50% 50%, #000 40%, transparent 100%)",
        }}
      />
      <div
        className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-primary-container/10 rounded-full blur-[120px] pointer-events-none"
      />

      {/* Top Bar Status */}
      <header className="relative z-10 w-full px-6 py-4 flex items-center justify-between border-b border-outline-variant/20 bg-surface-container-lowest/60 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 rounded-lg bg-surface-container-high border border-outline-variant/40 flex items-center justify-center shadow-[0_0_10px_rgba(225,29,72,0.3)]">
            <DanteLogo size={16} glow={false} />
          </div>
          <div className="flex items-center gap-2 font-code-sm text-code-sm">
            <span className="font-bold tracking-wider text-on-surface">D.A.N.T.E.</span>
            <span className="text-surface-container-highest">/</span>
            <span className="text-outline uppercase">Auth Gateway</span>
          </div>
        </div>

        <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-surface-container-low border border-outline-variant/30 text-code-sm font-code-sm">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-tertiary opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-tertiary"></span>
          </span>
          <span className="text-on-surface-variant text-[11px] font-mono">SECOPS COMMAND ONLINE</span>
        </div>
      </header>

      {/* Main Authentication Center Card */}
      <main className="relative z-10 flex-1 flex items-center justify-center px-4 py-8">
        <div className="w-full max-w-[430px]">
          {/* Outer Border Glow Frame */}
          <div className="relative rounded-2xl bg-surface-container-lowest border border-outline-variant/40 shadow-[0_24px_50px_rgba(0,0,0,0.8),0_0_30px_rgba(225,29,72,0.12)] overflow-hidden">
            {/* Top Cardinal Crimson Indicator Line */}
            <div className="h-0.5 w-full bg-gradient-to-r from-transparent via-primary-container to-transparent" />

            <div className="p-8 sm:p-9 space-y-6">
              {/* Header with Dante Logo and Badge Frame */}
              <div className="text-center space-y-3">
                <div className="inline-flex items-center justify-center mb-1">
                  <div className="relative p-3.5 rounded-2xl bg-surface-container-low border border-primary-container/30 shadow-[0_0_24px_rgba(225,29,72,0.25)] ring-1 ring-primary-container/20">
                    <DanteLogo size={58} glow={true} />
                  </div>
                </div>

                <div className="space-y-1">
                  <h1 className="font-headline-xl text-2xl font-bold tracking-widest text-on-surface">
                    D.A.N.T.E.
                  </h1>
                  <p className="font-code-sm text-xs font-semibold tracking-wider text-primary uppercase">
                    Detection &amp; Alerting Navigator for Threat Engineering
                  </p>
                </div>

                <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                  Terminal tático de monitoramento, curadoria de regras e resposta a ameaças.
                </p>
              </div>

              {/* Error Notice */}
              {error && (
                <div className="flex items-start gap-2.5 p-3 rounded-lg bg-error-container/20 border border-error/30 text-error font-body-sm text-body-sm animate-shake">
                  <span className="material-symbols-outlined text-[18px] shrink-0 mt-0.5 text-error">
                    error
                  </span>
                  <div className="flex-1 text-left">{error}</div>
                </div>
              )}

              {/* Authentication Form */}
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-1.5 text-left">
                  <label
                    htmlFor="username"
                    className="block font-code-sm text-xs font-medium uppercase tracking-wider text-on-surface-variant"
                  >
                    Identificador de Operador
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-outline">
                      <span className="material-symbols-outlined text-[18px]">badge</span>
                    </div>
                    <input
                      id="username"
                      type="text"
                      className="w-full pl-9 pr-3 py-2.5 bg-surface-container-low border border-outline-variant/40 rounded-lg font-mono text-sm text-on-surface placeholder:text-outline focus:outline-none focus:border-primary-container focus:ring-1 focus:ring-primary-container transition-all"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="operador@dante.local"
                      required
                      autoFocus
                    />
                  </div>
                </div>

                <div className="space-y-1.5 text-left">
                  <div className="flex items-center justify-between">
                    <label
                      htmlFor="password"
                      className="block font-code-sm text-xs font-medium uppercase tracking-wider text-on-surface-variant"
                    >
                      Chave de Acesso
                    </label>
                    <span className="font-code-sm text-[10px] text-outline uppercase tracking-wider">
                      SHA256 Token
                    </span>
                  </div>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-outline">
                      <span className="material-symbols-outlined text-[18px]">key</span>
                    </div>
                    <input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      className="w-full pl-9 pr-10 py-2.5 bg-surface-container-low border border-outline-variant/40 rounded-lg font-mono text-sm text-on-surface placeholder:text-outline focus:outline-none focus:border-primary-container focus:ring-1 focus:ring-primary-container transition-all"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center text-outline hover:text-on-surface transition-colors"
                      tabIndex={-1}
                    >
                      <span className="material-symbols-outlined text-[18px]">
                        {showPassword ? "visibility_off" : "visibility"}
                      </span>
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-2 inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-primary-container hover:bg-inverse-primary text-on-primary-container font-headline-sm font-semibold tracking-wide shadow-[0_0_16px_rgba(225,29,72,0.35)] transition-all active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <>
                      <span className="material-symbols-outlined text-[18px] animate-spin">
                        progress_activity
                      </span>
                      <span>Autenticando Operador...</span>
                    </>
                  ) : (
                    <>
                      <span className="material-symbols-outlined text-[18px]">login</span>
                      <span>Acessar Console D.A.N.T.E.</span>
                    </>
                  )}
                </button>
              </form>

              {/* Security Context Badge */}
              <div className="pt-4 border-t border-outline-variant/20 flex items-center justify-center gap-2 text-code-sm text-[11px] text-outline">
                <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
                <span>Ambiente Seguro • Zero-Trust Session &amp; CSRF Protected</span>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer System Info */}
      <footer className="relative z-10 w-full px-6 py-3 border-t border-outline-variant/20 bg-surface-container-lowest/60 backdrop-blur-md flex flex-col sm:flex-row items-center justify-between gap-2 text-code-sm text-[11px] text-outline">
        <div>
          <span>D.A.N.T.E. Framework • Engine de Detecção & Telemetria</span>
        </div>
        <div className="flex items-center gap-3">
          <span>Cluster: <span className="text-on-surface-variant font-mono">wazuh-siem-prod</span></span>
          <span>•</span>
          <span>Regras: <span className="text-on-surface-variant font-mono">Ruler 5m Baseline</span></span>
        </div>
      </footer>
    </div>
  );
};
