# Plugin: Google Stitch MCP Server

Este plugin integra o **Google Stitch** (plataforma de geração e design de interfaces assistida por IA) ao agente do Antigravity via **Model Context Protocol (MCP)**.

---

## 🛠️ O que este MCP Server oferece?

Com o MCP Server do Google Stitch ativo, o agente pode:
- **`get_screen_code`**: Baixar e inspecionar o código HTML/CSS e componentes de qualquer tela criada no Stitch.
- **`get_screen_image`**: Recuperar capturas de tela das interfaces desenhadas para inspeção visual.
- **`build_site`**: Mapear telas do Stitch diretamente para rotas do frontend (como React ou Astro), acelerando o desenvolvimento.
- **`create_project`**: Criar projetos no Stitch e iniciar novos designs programaticamente.
- **Acessar tokens de design**: Consultar tipografia, paleta de cores e espaçamentos definidos no seu design system.

---

## 🔑 Como Obter e Inserir sua API Key

### 1. Obtenção da API Key no Google Stitch
1. Acesse o portal do [Google Stitch](https://stitch.withgoogle.com/).
2. Faça login com sua conta Google.
3. Abra as configurações da conta / projeto (ícone de engrenagem ou menu de perfil).
4. Navegue até a seção de **API Keys** e clique em **Create API Key**.
5. Copie a chave gerada imediatamente.

---

### 2. Onde Configurar a Chave (3 Métodos Suportados)

#### Método A: No arquivo `.env` do projeto (Recomendado para o Workspace)
O utilitário `@_davideast/stitch-mcp` lê automaticamente variáveis do arquivo `.env` localizado na raiz do projeto. Como `.env` está configurado no `.gitignore`, sua chave nunca será versionada acidentalmente:

Abra o arquivo `.env` na raiz do projeto e defina:
```env
STITCH_API_KEY=sua_chave_aqui
```

#### Método B: Na Configuração Global do Antigravity
Se preferir que a chave esteja disponível em todas as sessões e projetos nesta máquina:
1. Abra ou edite o arquivo `~/.gemini/config/mcp_config.json` (ou no Antigravity: clique no menu `...` > **MCP Servers** > **Manage MCP Servers** > **View raw config**).
2. Insira a sua chave diretamente na propriedade `env`:
```json
{
  "mcpServers": {
    "stitch": {
      "command": "npx",
      "args": ["-y", "@_davideast/stitch-mcp", "proxy"],
      "env": {
        "STITCH_API_KEY": "sua_chave_aqui"
      }
    }
  }
}
```

#### Método C: Variável de Ambiente do Sistema
Você também pode definir a variável `STITCH_API_KEY` diretamente no seu ambiente do sistema operacional (Windows/Linux/macOS):

- **PowerShell (sessão atual)**:
  ```powershell
  $env:STITCH_API_KEY = "sua_chave_aqui"
  ```
- **PowerShell (persistente no Windows)**:
  ```powershell
  [System.Environment]::SetEnvironmentVariable('STITCH_API_KEY', 'sua_chave_aqui', 'User')
  ```

---

## 🚀 Como Inicializar / Recarregar no Antigravity

1. Após configurar sua chave em um dos métodos acima:
2. No Antigravity, clique nas opções adicionais (`...`) no canto superior direito do painel de chat.
3. Acesse **MCP Servers**. O servidor `stitch` aparecerá na lista de servidores disponíveis.
4. Reinicie ou recarregue a janela do Antigravity se necessário para registrar os novos comandos e ferramentas.
