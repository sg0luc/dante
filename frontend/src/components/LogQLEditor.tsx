import React, { useEffect, useRef, useState } from "react";

export interface LogQLFunctionItem {
  name: string;
  category: "aggregation" | "parser" | "filter" | "label";
  signature: string;
  insertText: string;
  cursorOffset?: number; // Posição relativa do cursor após inserção
  description: string;
}

export const GRAFANA_LOGQL_FUNCTIONS: LogQLFunctionItem[] = [
  // Funções de agregação de range / vetor métrico
  {
    name: "count_over_time",
    category: "aggregation",
    signature: "count_over_time([range])",
    insertText: "count_over_time()",
    cursorOffset: 16,
    description: "Conta o número de entradas de log dentro da janela de tempo.",
  },
  {
    name: "rate",
    category: "aggregation",
    signature: "rate([range])",
    insertText: "rate()",
    cursorOffset: 5,
    description: "Calcula o número de entradas de log por segundo.",
  },
  {
    name: "bytes_over_time",
    category: "aggregation",
    signature: "bytes_over_time([range])",
    insertText: "bytes_over_time()",
    cursorOffset: 16,
    description: "Soma o número de bytes nas linhas dentro da janela de tempo.",
  },
  {
    name: "bytes_rate",
    category: "aggregation",
    signature: "bytes_rate([range])",
    insertText: "bytes_rate()",
    cursorOffset: 11,
    description: "Calcula a taxa de bytes por segundo no stream de logs.",
  },
  {
    name: "sum",
    category: "aggregation",
    signature: "sum()",
    insertText: "sum()",
    cursorOffset: 4,
    description: "Agrega e soma valores ou séries ao longo dos streams.",
  },
  {
    name: "avg",
    category: "aggregation",
    signature: "avg()",
    insertText: "avg()",
    cursorOffset: 4,
    description: "Calcula a média dos valores ao longo das séries agrupadas.",
  },
  {
    name: "min",
    category: "aggregation",
    signature: "min()",
    insertText: "min()",
    cursorOffset: 4,
    description: "Identifica o menor valor das séries na janela calculada.",
  },
  {
    name: "max",
    category: "aggregation",
    signature: "max()",
    insertText: "max()",
    cursorOffset: 4,
    description: "Identifica o maior valor das séries na janela calculada.",
  },
  // Parsers de pipeline
  {
    name: "json",
    category: "parser",
    signature: "| json",
    insertText: "| json",
    cursorOffset: 6,
    description: "Decodifica linhas em JSON e extrai chaves como campos/labels.",
  },
  {
    name: "logfmt",
    category: "parser",
    signature: "| logfmt",
    insertText: "| logfmt",
    cursorOffset: 8,
    description: "Extrai pares chave=valor no formato padrão logfmt.",
  },
  {
    name: "unpack",
    category: "parser",
    signature: "| unpack",
    insertText: "| unpack",
    cursorOffset: 8,
    description: "Desempacota campos codificados com Promtail unpack.",
  },
  {
    name: "pattern",
    category: "parser",
    signature: '| pattern "<pattern>"',
    insertText: '| pattern "<_>"',
    cursorOffset: 11,
    description: "Extrai campos de linhas não estruturadas via padrão customizado.",
  },
  {
    name: "regexp",
    category: "parser",
    signature: '| regexp "<re>"',
    insertText: '| regexp "(?P<field>.*)"',
    cursorOffset: 16,
    description: "Extrai campos nomeados via expressão regular RE2 da telemetria.",
  },
  {
    name: "decolorize",
    category: "parser",
    signature: "| decolorize",
    insertText: "| decolorize",
    cursorOffset: 12,
    description: "Remove sequências de escape ANSI/cores do log.",
  },
  // Formatação e labels
  {
    name: "line_format",
    category: "filter",
    signature: '| line_format "{{.field}}"',
    insertText: '| line_format "{{.}}" ',
    cursorOffset: 18,
    description: "Reescreve o corpo da linha de log usando templates Go.",
  },
  {
    name: "label_format",
    category: "label",
    signature: '| label_format dst=src',
    insertText: "| label_format ",
    cursorOffset: 15,
    description: "Renomeia, modifica ou cria labels interpoladas.",
  },
  {
    name: "unwrap",
    category: "parser",
    signature: "| unwrap <field>",
    insertText: "| unwrap ",
    cursorOffset: 9,
    description: "Converte um campo extraído em valor numérico para agregação métrica.",
  },
];

interface LogQLEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  height?: string;
  required?: boolean;
}

export const LogQLEditor: React.FC<LogQLEditorProps> = ({
  value,
  onChange,
  placeholder,
  height = "130px",
  required = false,
}) => {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Estado do autocomplete
  const [suggestions, setSuggestions] = useState<LogQLFunctionItem[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [activeWordRange, setActiveWordRange] = useState<{ start: number; end: number } | null>(null);
  const [showDropdown, setShowDropdown] = useState(false);

  // Detecta a palavra imediatamente antes do cursor para sugerir funções
  const updateSuggestions = (text: string, cursorPos: number) => {
    // Procura palavra/símbolo sendo digitado antes do cursor
    const textBefore = text.slice(0, cursorPos);
    // Combina caracteres alfanuméricos e underscores ou um pipe inicial
    const match = textBefore.match(/(?:\||\b)([a-zA-Z0-9_]*)$/);
    if (!match || match[0].length === 0) {
      setShowDropdown(false);
      setSuggestions([]);
      setActiveWordRange(null);
      return;
    }

    const queryWord = match[1].toLowerCase();
    const isPipePrefix = match[0].startsWith("|");

    let filtered = GRAFANA_LOGQL_FUNCTIONS.filter((fn) => {
      if (isPipePrefix) {
        return fn.category === "parser" || fn.category === "filter" || fn.category === "label";
      }
      return fn.name.toLowerCase().includes(queryWord);
    });

    // Se começou com letra ou pipe, exibe sugestões
    if (queryWord.length > 0 || isPipePrefix) {
      if (queryWord.length > 0) {
        filtered = filtered.filter((fn) =>
          fn.name.toLowerCase().startsWith(queryWord) || fn.name.toLowerCase().includes(queryWord)
        );
      }
      if (filtered.length > 0) {
        setSuggestions(filtered);
        setSelectedIndex(0);
        setActiveWordRange({
          start: cursorPos - match[0].length,
          end: cursorPos,
        });
        setShowDropdown(true);
        return;
      }
    }

    setShowDropdown(false);
    setSuggestions([]);
    setActiveWordRange(null);
  };

  const applySuggestion = (fn: LogQLFunctionItem) => {
    const textarea = textareaRef.current;
    if (!textarea || !activeWordRange) return;

    const before = value.substring(0, activeWordRange.start);
    const after = value.substring(activeWordRange.end);

    // Ajusta espaçamento se for estágio de pipe e já houver espaço
    let insert = fn.insertText;
    if (before.endsWith("| ") && insert.startsWith("| ")) {
      insert = insert.replace(/^\|\s*/, "");
    } else if (before.endsWith("|") && insert.startsWith("| ")) {
      insert = insert.replace(/^\|/, "");
    }

    const nextValue = before + insert + after;
    onChange(nextValue);

    const newCursor = activeWordRange.start + (fn.cursorOffset ?? insert.length);
    setTimeout(() => {
      textarea.focus();
      textarea.setSelectionRange(newCursor, newCursor);
    }, 0);

    setShowDropdown(false);
    setSuggestions([]);
    setActiveWordRange(null);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    const textarea = e.currentTarget;
    const { selectionStart, selectionEnd, value: curValue } = textarea;

    // Navegação no dropdown de autocomplete aberto
    if (showDropdown && suggestions.length > 0) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev + 1) % suggestions.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev - 1 + suggestions.length) % suggestions.length);
        return;
      }
      if (e.key === "Enter" || e.key === "Tab") {
        e.preventDefault();
        applySuggestion(suggestions[selectedIndex]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setShowDropdown(false);
        return;
      }
    }

    // Pares de caracteres para auto-fechamento
    const pairMap: Record<string, string> = {
      "(": ")",
      "{": "}",
      "[": "]",
      '"': '"',
      "`": "`",
    };

    if (e.key in pairMap) {
      e.preventDefault();
      const closeChar = pairMap[e.key];
      const selectedText = curValue.substring(selectionStart, selectionEnd);
      const nextValue =
        curValue.substring(0, selectionStart) +
        e.key +
        selectedText +
        closeChar +
        curValue.substring(selectionEnd);

      onChange(nextValue);

      setTimeout(() => {
        textarea.selectionStart = selectionStart + 1;
        textarea.selectionEnd = selectionStart + 1 + selectedText.length;
        updateSuggestions(nextValue, selectionStart + 1);
      }, 0);
      return;
    }

    // Se o usuário digitar o caractere de fechamento logo antes dele mesmo, apenas avança o cursor
    if ([")", "}", "]", '"', "`"].includes(e.key)) {
      if (selectionStart === selectionEnd && curValue[selectionStart] === e.key) {
        e.preventDefault();
        textarea.selectionStart = selectionStart + 1;
        textarea.selectionEnd = selectionStart + 1;
        updateSuggestions(curValue, selectionStart + 1);
        return;
      }
    }

    // Auto-indentação ao pressionar Enter mantendo identação do bloco
    if (e.key === "Enter") {
      e.preventDefault();
      const currentLineStart = curValue.lastIndexOf("\n", selectionStart - 1) + 1;
      const currentLine = curValue.substring(currentLineStart, selectionStart);
      const indentMatch = currentLine.match(/^\s*/);
      const currentIndent = indentMatch ? indentMatch[0] : "";

      // Se o último caractere digitado foi '{' ou '(', adiciona indentação de 4 espaços
      const lastChar = curValue.substring(0, selectionStart).trim().slice(-1);
      const extraIndent = ["{", "("].includes(lastChar) ? "    " : "";
      const indentToAdd = "\n" + currentIndent + extraIndent;

      const nextValue =
        curValue.substring(0, selectionStart) + indentToAdd + curValue.substring(selectionEnd);
      onChange(nextValue);

      setTimeout(() => {
        textarea.selectionStart = selectionStart + indentToAdd.length;
        textarea.selectionEnd = selectionStart + indentToAdd.length;
        updateSuggestions(nextValue, selectionStart + indentToAdd.length);
      }, 0);
      return;
    }

    // Indentação com tecla Tab (4 espaços para indentação estruturada)
    if (e.key === "Tab") {
      e.preventDefault();
      const tabSpaces = "    ";
      const nextValue =
        curValue.substring(0, selectionStart) + tabSpaces + curValue.substring(selectionEnd);
      onChange(nextValue);

      setTimeout(() => {
        textarea.selectionStart = selectionStart + tabSpaces.length;
        textarea.selectionEnd = selectionStart + tabSpaces.length;
        updateSuggestions(nextValue, selectionStart + tabSpaces.length);
      }, 0);
      return;
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const nextVal = e.target.value;
    const cursorPos = e.target.selectionStart;
    onChange(nextVal);
    updateSuggestions(nextVal, cursorPos);
  };

  const handleSelect = (e: React.SyntheticEvent<HTMLTextAreaElement>) => {
    const target = e.currentTarget;
    updateSuggestions(target.value, target.selectionStart);
  };

  // Fecha o dropdown se clicar fora
  useEffect(() => {
    const handleOutsideClick = (evt: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(evt.target as Node) &&
        textareaRef.current &&
        !textareaRef.current.contains(evt.target as Node)
      ) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handleOutsideClick);
    return () => document.removeEventListener("mousedown", handleOutsideClick);
  }, []);

  return (
    <div style={{ position: "relative", width: "100%" }}>
      <textarea
        ref={textareaRef}
        className="input"
        style={{
          width: "100%",
          height,
          fontFamily: "var(--font-mono)",
          fontSize: "0.85rem",
          lineHeight: "1.45",
          tabSize: 4,
          whiteSpace: "pre",
          resize: "vertical",
        }}
        value={value}
        onKeyDown={handleKeyDown}
        onChange={handleChange}
        onSelect={handleSelect}
        placeholder={placeholder}
        required={required}
        spellCheck={false}
      />

      {/* Menu flutuante de Autocomplete de Funções LogQL */}
      {showDropdown && suggestions.length > 0 && (
        <div
          ref={dropdownRef}
          style={{
            position: "absolute",
            bottom: "100%",
            left: "0",
            marginBottom: "6px",
            backgroundColor: "var(--bg-surface-elevated)",
            border: "1px solid var(--border-color-focus)",
            borderRadius: "8px",
            boxShadow: "0 8px 24px rgba(0, 0, 0, 0.6), 0 0 12px rgba(225, 29, 72, 0.15)",
            zIndex: 1050,
            width: "360px",
            maxHeight: "220px",
            overflowY: "auto",
          }}
        >
          <div
            style={{
              padding: "6px 10px",
              fontSize: "0.72rem",
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              color: "var(--text-subtle)",
              borderBottom: "1px solid var(--border-color-subtle)",
              display: "flex",
              justifyContent: "space-between",
            }}
          >
            <span>Funções LogQL da Engine</span>
            <span style={{ fontSize: "0.68rem" }}>↑↓ Navegar • Enter / Tab Aplicar</span>
          </div>
          {suggestions.map((fn, index) => {
            const isSelected = index === selectedIndex;
            return (
              <div
                key={fn.name}
                onMouseDown={(e) => {
                  e.preventDefault();
                  applySuggestion(fn);
                }}
                onMouseEnter={() => setSelectedIndex(index)}
                style={{
                  padding: "6px 10px",
                  cursor: "pointer",
                  backgroundColor: isSelected ? "rgba(225, 29, 72, 0.16)" : "transparent",
                  borderLeft: isSelected ? "3px solid var(--primary)" : "3px solid transparent",
                  transition: "background 0.1s ease",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.82rem",
                      fontWeight: 600,
                      color: isSelected ? "#ffffff" : "var(--text-main)",
                    }}
                  >
                    {fn.name}
                  </span>
                  <span
                    style={{
                      fontSize: "0.68rem",
                      padding: "1px 6px",
                      borderRadius: "4px",
                      backgroundColor:
                        fn.category === "aggregation"
                          ? "rgba(59, 130, 246, 0.15)"
                          : fn.category === "parser"
                          ? "rgba(16, 185, 129, 0.15)"
                          : "rgba(168, 85, 247, 0.15)",
                      color:
                        fn.category === "aggregation"
                          ? "var(--status-low)"
                          : fn.category === "parser"
                          ? "var(--status-normal)"
                          : "var(--status-silenced)",
                    }}
                  >
                    {fn.category}
                  </span>
                </div>
                <div
                  style={{
                    fontSize: "0.72rem",
                    color: "var(--text-muted)",
                    marginTop: "2px",
                    lineHeight: "1.2",
                  }}
                >
                  {fn.description}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
