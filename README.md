# ⚡ NetPulse - Network Analyzer & Sentinel Dashboard

Uma aplicação web completa, profissional e com acabamento de nível empresarial para inventário de dispositivos, medição de latência do router em tempo real, deteção de portas abertas, testes de velocidade de internet e alertas de novos dispositivos na tua rede de casa.

---

## 🚀 Como Iniciar

Podes iniciar o NetPulse com um único comando no teu terminal:

```bash
cd /Users/andrebarroso/Documents/Rede
./start.sh
```

Ou diretamente com Python:

```bash
python3 server.py
```

O servidor iniciará instantaneamente em **`http://localhost:8888`** e estará acessível em qualquer outro dispositivo da tua rede local (ex: smartphone, tablet ou outro PC) pelo teu endereço IP local (ex: `http://192.168.1.68:8888`).

---

## 🌟 Funcionalidades Implementadas

### 1. Inventário Completo de Dispositivos
- **Listagem detalhada**: Endereço IP, MAC Address normalizado, Fabricante (resolvido por base de dados OUI offline com mais de 3.000 fabricantes), Hostname DNS/mDNS e Estado (Online/Offline).
- **Categorização Automática Inteligente**:
  - 🌐 **Routers & Infraestrutura de Rede**: Gateway MEO/Altice/NOS/Vodafone (Arcadyan, Sagemcom, Huawei, TP-Link, Ubiquiti).
  - 📱 **Smartphones & Tablets**: Apple iPhones/iPads, Samsung Galaxy, Xiaomi, Huawei, etc.
  - 💻 **Computadores & Servidores**: MacBooks, PCs Intel, estações Windows e Linux.
  - 📺 **Smart TVs & Streaming**: Apple TV, Google Chromecast, Amazon Fire TV, Smart TVs Samsung/LG/Sony.
  - 💡 **IoT & Smart Home**: Philips Hue, lâmpadas e tomadas inteligentes Espressif (ESP32/ESP8266), Sonoff, Shelly.
  - 🎮 **Consolas de Jogos**: PlayStation, Xbox, Nintendo Switch.
  - 🖨️ **Impressoras de Rede**: HP, Epson, Canon, Brother.
- **Detetor de Endereços Privados (Randomized MACs)**: Identifica automaticamente smartphones iOS e Android a utilizar "Endereço Wi-Fi Privado".
- **Personalização de Dispositivos**: Permite atribuir nomes personalizados (ex: *"iPhone do André"*, *"Lâmpada da Sala"*) e notas técnicas.
- **Vistas Adaptáveis**: Alternância instantânea entre **Vista em Tabela** (para análise técnica) e **Vista em Grelha** (Cards visuais).

### 2. Alertas de Segurança & Novos Dispositivos
- Cada novo dispositivo desconhecido que entra na rede Wi-Fi é sinalizado com um badge luminoso **"NOVO"** e registado na central de auditoria de segurança.
- Notificações com badge animado no cabeçalho.
- Ação com 1 clique para *"Reconhecer / Marcar como Confiável"*.

### 3. Auditoria de Portas Abertas (Port Scanner)
- Varrimento TCP multithreaded de alta velocidade para serviços comuns em qualquer dispositivo:
  - Web (80 HTTP, 443 HTTPS, 8080, 8443)
  - Acesso remoto (22 SSH, 23 Telnet, 3389 RDP)
  - Partilha de ficheiros e multimédia (445 SMB, 548 AFP, 5000 Synology)
  - Câmaras e Streaming (554 RTSP)
  - Impressão direta (9100 RAW, 631 IPP)
  - IoT Brokers (1883 MQTT)
- Classificação de risco de segurança (Informativo, Médio ou Elevado).

### 4. Monitor de Latência do Router e Estabilidade Wi-Fi
- Medição contínua de latência para o Router (`192.168.1.1`) e para a Internet (`1.1.1.1` Cloudflare).
- Gráfico interativo em tempo real com Chart.js.
- Cálculo de **Jitter** (estabilidade de sinal Wi-Fi) e **Perda de Pacotes (Packet Loss %)**.

### 5. Sistema de Agentes Autónomos de Rede (AI & Heuristic Agents)
- **Sentinela de Novos Dispositivos (`sentinel`)**: Monitorização ativa de novos MACs e IPs na rede local com alerta instantâneo.
- **Auditor de Segurança e Portas (`security_auditor`)**: Avaliação contínua de vulnerabilidades e serviços críticos expostos (Telnet, SMB, RTSP).
- **Estilista de Marcas e OUI (`brand_stylist`)**: Mapeamento inteligente de fabricantes com base em 30.000+ prefixos IEEE OUI e identificação vetorial autêntica.
- **Forense de Rede e MAC Spoofing (`forensics`)**: Deteção de endereços MAC falsificados, gateways fraudulentos e anomalias de hardware.
- **Sentinela de QoS e Latência (`qos_sentinel`)**: Deteção precoce de jitter excessivo e degradação de sinal Wi-Fi.
- **Consola de Missões**: Registo auditável em direto de todas as execuções dos agentes com alternadores táteis na UI.

### 6. Teste de Velocidade de Internet (Speedtest Engine)
- Medidor integrado de throughput real:
  - Débito de Download (Mbps)
  - Débito de Upload (Mbps)
  - Latência e Jitter
- Gauge / mostrador visual animado.
- Histórico dos testes guardado na base de dados SQLite.

### 7. Interface Executiva Cyber Glass 2.0
- **Estética de Alta Densidade**: Fundo atmosférico com gradientes radiais, efeito vidro translúcido (`backdrop-filter: blur(16px)`), e realces de borda.
- **Logótipos Oficiais Vetoriais**: MEO no router principal, Apple, Samsung, Xiaomi, Home Assistant, Alexa, Unraid, TrueNAS, NVIDIA, Philips Hue, etc.
- **Interatividade & Ergonomia**: Cópia rápida de IP/MAC com feedback de toast flutuante e tabela de alta legibilidade.

---

## 🛠️ Tecnologias Utilizadas

- **Backend**: Python 3 nativo (zero dependências externas pesadas — sem necessidade de pip install complexos).
- **Base de Dados**: SQLite embutido (`netpulse.db`) com histórico e inventário persistidos.
- **Frontend**: Single Page Application com Tailwind CSS, Lucide Icons, Chart.js e Cyber Glass 2.0 Design System.

---

## 🐳 Instalação em Docker & Unraid

### Imagem Oficial no GHCR
```bash
ghcr.io/barroso88/netpulse:latest
```

> **IMPORTANTE**: O NetPulse necessita de correr em modo de rede **`host`** (`--net=host`) para aceder diretamente à tabela ARP física da rede local e medir o tráfego dos equipamentos em LAN.

### Método 1: Unraid Docker Tab (Recomendado)
1. No Unraid, vá ao separador **Docker** e clique em **Add Container**.
2. Preencha os seguintes parâmetros:
   - **Name**: `netpulse`
   - **Repository**: `ghcr.io/barroso88/netpulse:latest`
   - **Network Type**: `Host`
   - **Privileged**: `ON` (necessário para pacotes de ping ICMP de baixo nível)
   - **Port**: `8888`
   - **Volume Mapping**:
     - *Container Path*: `/data`
     - *Host Path*: `/mnt/user/appdata/netpulse`
3. Clique em **Apply**. O NetPulse iniciará e ficará acessível em `http://IP-DO-UNRAID:8888`.

*(Em alternativa, pode copiar o ficheiro `unraid-template.xml` deste repositório para `/boot/config/plugins/dockerMan/templates-user/my-NetPulse.xml` na sua pen flash do Unraid para carregar o modelo pré-configurado).*

### Método 2: Docker Run
```bash
docker run -d \
  --name netpulse \
  --restart unless-stopped \
  --net=host \
  --privileged \
  -v /mnt/user/appdata/netpulse:/data \
  ghcr.io/barroso88/netpulse:latest
```

### Método 3: Docker Compose
```yaml
services:
  netpulse:
    image: ghcr.io/barroso88/netpulse:latest
    container_name: netpulse
    restart: unless-stopped
    network_mode: host
    privileged: true
    volumes:
      - /mnt/user/appdata/netpulse:/data
```


