# 🛡️ SOC104 – Malware Detected | Investigação de Incidente (LetsDefend)

![Severity](https://img.shields.io/badge/Severity-High-red)
![Type](https://img.shields.io/badge/Type-Malware-orange)
![Status](https://img.shields.io/badge/Status-Closed%20%2F%20Contained-brightgreen)
![Platform](https://img.shields.io/badge/Platform-LetsDefend-blue)

> Documentação completa (passo a passo) de uma investigação de segurança realizada na plataforma de treinamento **LetsDefend**, referente ao alerta **SOC104 – Malware Detected**. Este repositório tem fins educacionais e de portfólio, demonstrando o processo de triagem, análise e resposta a incidentes (SOC Analyst / Blue Team).

---

## 📌 Sumário

- [Visão Geral do Alerta](#-visão-geral-do-alerta)
- [Ferramentas Utilizadas](#-ferramentas-utilizadas)
- [Metodologia de Investigação](#-metodologia-de-investigação)
  - [1. Triagem do Alerta](#1️⃣-triagem-do-alerta)
  - [2. Análise do Arquivo (VirusTotal)](#2️⃣-análise-do-arquivo-virustotal)
  - [3. Análise do Endpoint (EDR)](#3️⃣-análise-do-endpoint-edr)
  - [4. Análise de Logs de Rede (Log Management)](#4️⃣-análise-de-logs-de-rede-log-management)
  - [5. Reputação do IP de Destino (C2)](#5️⃣-reputação-do-ip-de-destino-c2)
  - [6. Criação do Incidente e Execução do Playbook](#6️⃣-criação-do-incidente-e-execução-do-playbook)
  - [7. Contenção do Host](#7️⃣-contenção-do-host)
  - [8. Nota Final do Analista](#8️⃣-nota-final-do-analista)
- [Indicadores de Comprometimento (IOCs)](#-indicadores-de-comprometimento-iocs)
- [Linha do Tempo (Timeline)](#-linha-do-tempo-timeline)
- [Veredito Final](#-veredito-final)
- [Lições Aprendidas / Recomendações](#-lições-aprendidas--recomendações)
- [Screenshots](#-screenshots)

---

## 📋 Visão Geral do Alerta

<img width="1226" height="596" alt="Captura de tela 2026-07-14 170303" src="https://github.com/user-attachments/assets/d1c96269-45dc-4618-8e8f-38e81d472340" />

---
| Campo | Valor |
|---|---|
| **EventID** | 36 |
| **Regra (Rule)** | SOC104 - Malware Detected |
| **Data/Hora do Evento** | 01/Dez/2020, 10:23 AM |
| **Severidade** | High |
| **Nível** | Security Analyst |
| **Endereço de Origem** | 10.15.15.18 |
| **Hostname de Origem** | AdamPRD |
| **Nome do Arquivo** | Invoice.exe |
| **Hash do Arquivo (MD5)** | `f83fb9ce6a83da58b20685c1d7e1e546` |
| **Tamanho do Arquivo** | 473.00 KB |
| **Ação do Dispositivo** | Allowed |
| **Arquivo (Password:infected)** | Download |

> ⚠️ O nome do arquivo (**Invoice.exe** — "Fatura.exe") é um clássico indicativo de **phishing/engenharia social**, tentando induzir o usuário a executar um anexo malicioso disfarçado de fatura/boleto.

---

## 🧰 Ferramentas Utilizadas

- **LetsDefend SIEM** (Main/Investigation Channel)
- **Log Management** (Busca por Source Address / eventos de proxy)
- **EDR / Endpoint Security** (Informações do host, containment)
- **VirusTotal** (Análise de hash e IP)
- **Playbook interno do SOC104** (Fluxo guiado de resposta a incidente)

---

## 🔍 Metodologia de Investigação

### 1️⃣ Triagem do Alerta
O alerta **EventID 36** foi recebido no **Investigation Channel** classificado como **High severity**, indicando que o host `AdamPRD` (IP `10.15.15.18`) havia feito o download do arquivo `Invoice.exe`, que foi **permitido (Allowed)** pelo controle de segurança.
### 2️⃣ Análise do Arquivo (VirusTotal)
O hash do arquivo foi submetido ao **VirusTotal**, retornando:

<img width="1520" height="696" alt="Captura de tela 2026-07-14 170354" src="https://github.com/user-attachments/assets/f6420b72-8fbc-49f4-8ca7-2391e03c12de" />

---
- **63 / 70 vendors** classificaram o arquivo como **malicioso**.
- **Popular threat label:** `ransomware.maze/dump`
- **Threat categories:** `ransomware`, `trojan`, `adware`
- **Family labels:** `maze`, `dump`, `garrantdecrypt`

➡️ **Conclusão parcial:** o arquivo está associado à família de **ransomware MAZE**, uma ameaça conhecida por dupla extorsão (criptografia + exfiltração de dados).

### 3️⃣ Análise do Endpoint (EDR)
Consulta ao host `10.15.15.18` no módulo de **Endpoint Security**:

<img width="1245" height="527" alt="Captura de tela 2026-07-14 170445" src="https://github.com/user-attachments/assets/dfad4f10-5cd6-43de-a001-1b72e3ab730b" />

---
| Campo | Valor |
|---|---|
| Hostname | AdamPRD |
| Domínio | LetsDefend |
| Endereço IP | 10.15.15.18 |
| Bit Level | 64 |
| Sistema Operacional | Windows 10 |
| Usuário Primário | Adam |
| Client/Server | Client |
| Último Login | 01/Dez/2020, 03:21 PM |

Verificação de **Processos**, **Network Action**, **Terminal History** e **Browser History**: todos retornaram **"No Agent Installed"** — ou seja, não havia telemetria de endpoint disponível para correlacionar atividade local do processo malicioso.

<img width="1241" height="531" alt="Captura de tela 2026-07-14 171008" src="https://github.com/user-attachments/assets/10f303cf-b323-4424-9f44-d31f26bc5fad" />

---
### 4️⃣ Análise de Logs de Rede (Log Management)
Diante da ausência de dados do EDR, a investigação seguiu para o **Log Management**, filtrando por `Source Address contains "10.15.15.18"`. Foi identificado **1 evento de proxy**:

<img width="1201" height="628" alt="Captura de tela 2026-07-14 170601" src="https://github.com/user-attachments/assets/0dd70329-1b8b-443a-bb2f-a0a64115b55a" />

```
[Dec, 01, 2020, 10:30 AM]
source_address = 10.15.15.18
source_port = 49832
destination_address = 92.63.8.47
destination_port = 443
type = Proxy
URL=http://92.63.8.47/
```

➡️ Isso confirma que o host **se comunicou** com um endereço IP externo suspeito logo após o alerta de malware, um forte indício de **callback/beacon para C2 (Command and Control)**.

### 5️⃣ Reputação do IP de Destino (C2)
O IP `92.63.8.47` foi analisado no VirusTotal/AbuseIPDB:

<img width="1517" height="692" alt="Captura de tela 2026-07-14 170914" src="https://github.com/user-attachments/assets/b57cc04c-730d-4f58-bced-2e658a0228af" />

---
- **8 / 91 vendors** marcaram o IP como **malicioso**.
- **País:** Turquia (TR)
- **ASN:** AS44558 (Netonline Bilisim Sirketi LTD)
- **Contexto (Crowdsourced):** referência a artigo de Threat Intelligence — *"Navigating the MAZE – Tactics, Techniques and Procedures Associated with MAZE Ransomware"* (fonte: AlienVault OTX/ArcSight, ~2 anos antes da análise).
- **Classificação AbuseIPDB:** *Command and control of malware*.

➡️ **Conclusão:** o IP `92.63.8.47` é um servidor de **Command & Control (C2)** conhecido, associado às TTPs do ransomware **MAZE**.

### 6️⃣ Criação do Incidente e Execução do Playbook
Com evidências suficientes (hash malicioso + comunicação C2 confirmada), um **incidente** foi criado:

| Campo | Valor |
|---|---|
| Incident Name | EventID: 36 - [SOC104 - Malware Detected] |
| Incident Type | Malware |
| Criado em | Investigação SOC104 |

O **Playbook** guiado do SOC foi executado com as seguintes etapas e decisões:

<img width="1192" height="347" alt="Captura de tela 2026-07-14 171228" src="https://github.com/user-attachments/assets/75d96f45-7f35-4138-9a6f-3a1c680772ad" />

| Etapa do Playbook | Decisão do Analista | Justificativa |
|---|---|---|
| Malware quarantined/cleaned? | **Not Quarantined** | Arquivo foi permitido (Allowed) e não há evidência de quarentena automática |
| Analyze Malware (3rd party tools) | **Malicious** | Confirmado via VirusTotal (63/70) |
| Check if someone requested C2 | **Accessed** | Log de proxy confirmou acesso ao IP às 10:30 AM |
| Containment | **Host contido via EDR** | Necessário isolar o host para impedir propagação/exfiltração |

### 7️⃣ Contenção do Host
Acessando **Endpoint Security → AdamPRD (10.15.15.18)**, ativei a opção de **Containment**, isolando o host da rede para interromper qualquer comunicação adicional com o C2 e mitigar o risco de propagação lateral ou execução de payload de ransomware. O status final do host foi atualizado para **"Host Contained"**.

### 8️⃣ Nota Final do Analista
> *"We received an alert (EventID 36) at 10:23 AM on Dec 01, 2020, indicating that malware had been detected on a host. During the initial analysis, no browser or network history was available on the endpoint, since no EDR agent was installed. However, Log Management showed that at 10:30 AM the same day, the host accessed the URL http://92.63.8.47/, which we identified as an IOC. Based on this finding, the host was contained and secured."*

O playbook foi finalizado após o registro da nota e a confirmação da contenção.

---

## 🧾 Indicadores de Comprometimento (IOCs)

| Tipo | Indicador | Observação |
|---|---|---|
| Nome de arquivo | `Invoice.exe` | Iscas de phishing (tema: fatura) |
| Hash (MD5) | `f83fb9ce6a83da58b20685c1d7e1e546` | 63/70 detecções no VirusTotal — MAZE ransomware |
| IP (C2) | `92.63.8.47` | 8/91 detecções — AS44558, Turquia — C2 do MAZE |
| URL | `http://92.63.8.47/` | Endpoint de callback acessado às 10:30 AM |
| Host afetado | `AdamPRD` (10.15.15.18) | Windows 10, usuário "Adam" |

> Consulte também o arquivo [`IOCs.md`](./IOCs.md) para uma lista em formato consumível.

---

## ⏱ Linha do Tempo (Timeline)

```
10:23 AM  →  Host AdamPRD faz o download de Invoice.exe (permitido pelo controle de segurança)
10:23 AM  →  Alerta SOC104 "Malware Detected" é gerado (EventID 36)
10:30 AM  →  Log de proxy registra conexão do host ao IP 92.63.8.47:443 (C2)
   ...    →  Analista inicia a triagem no Investigation Channel
   ...    →  Hash analisado no VirusTotal → 63/70 maliciosos (MAZE ransomware)
   ...    →  Verificação de EDR (processos/rede/terminal/browser) → sem telemetria de agente
   ...    →  IP 92.63.8.47 analisado → confirmado como C2 conhecido (MAZE TTPs)
   ...    →  Incidente criado e Playbook executado
   ...    →  Host AdamPRD contido via EDR (Containment = ON)
   ...    →  Nota de análise registrada e caso encerrado
```

---

## ✅ Veredito Final

**🔴 Verdadeiro Positivo (True Positive) — Incidente Confirmado**

O host `AdamPRD` foi comprometido por um arquivo malicioso (`Invoice.exe`) associado ao **ransomware MAZE**, confirmado por múltiplas fontes de threat intelligence, e apresentou comunicação de rede com um servidor de **Command & Control** conhecido. O host foi **contido com sucesso**, prevenindo a possível execução completa da carga de ransomware, criptografia de arquivos e/ou exfiltração de dados.

---

## 💡 Lições Aprendidas / Recomendações

- **Bloquear anexos executáveis protegidos por senha** em gateways de e-mail — essa é uma técnica comum de evasão de sandbox/AV.
- **Reforçar a telemetria de EDR** nos endpoints: neste caso não havia agente instalado, o que impediu a análise de processos, rede local e histórico de navegador diretamente no host.
- **Bloquear proativamente IOCs conhecidos** (IP `92.63.8.47`) em firewall/proxy, já referenciado publicamente como C2 do MAZE.
- **Treinamento de conscientização (phishing)** para usuários sobre anexos do tipo "fatura/invoice".
- **Automatizar a checagem de hash/IP** contra VirusTotal/AbuseIPDB no momento da ingestão do alerta, reduzindo o tempo de triagem (MTTR).

---

## 🖼 Screenshots

Todas as evidências capturadas durante a investigação estão disponíveis na pasta [`screenshots.md`](./screenshots.md):

1. `01-alert-details-virustotal-file-hash-endpoint.png` — Detalhes do alerta, hash no VirusTotal, informações do endpoint
2. `02-network-history-log-management-proxy-event.png` — Ausência de agente no EDR + evento de proxy no Log Management
3. `03-ip-reputation-incident-creation.png` — Reputação do IP C2 + criação do incidente
4. `04-playbook-analyze-malware-check-c2.png` — Etapas do playbook (análise de malware e verificação de C2)
5. `05-analyst-summary-containment.png` — Resumo da análise e contenção do host

---

## ⚠️ Disclaimer

Esta análise foi realizada em ambiente de **treinamento/simulação** da plataforma [LetsDefend](https://letsdefend.io/), com fins exclusivamente educacionais para desenvolvimento de habilidades em **SOC / Blue Team / Threat Detection & Response**. Nenhum dado real de produção foi utilizado.

---
