"""
NetPulse - OUI Database & Device Classification Engine
Resolves MAC addresses to vendor manufacturers offline and categorizes device types.
"""

import re

# Comprehensive IEEE OUI dictionary for prominent networking, smart home, mobile, gaming and computing vendors
KNOWN_OUIS = {
    # Rede Local Especificidades (Identificações Fixas NetPulse)
    "3C:6D:66": "NVIDIA Corporation (SHIELD TV)",
    "48:B0:2D": "NVIDIA Corporation (SHIELD TV)",
    "2C:CF:67": "Raspberry Pi (Trading) Ltd",
    "8E:F4:57": "iXsystems (TrueNAS / Servidor NAS)",
    "04:7C:16": "Micro-Star INTL (MSI)",
    "34:5A:60": "Micro-Star INTL (MSI)",
    "FC:3C:D7": "Tuya Smart Inc. (Matter)",
    "14:7F:67": "LG Innotek (Smart TV Module)",
    "00:1E:B8": "Aloys, Inc (Box Formuler IPTV)",
    "8C:D0:B2": "Beijing Xiaomi Mobile (Xiaomi)",
    "A8:51:AB": "Apple, Inc.",
    "A4:F6:E8": "Apple, Inc.",
    "7C:64:56": "Samsung Electronics",
    "68:72:C3": "Samsung Electronics",
    "F0:F5:BD": "Espressif Systems (Matter)",
    "44:5D:5E": "Sonoff / eWeLink (Coolkit)",
    "E8:F6:0A": "Sonoff / eWeLink (Espressif)",
    "94:E2:3C": "Intel Corporate (PC Windows)",
    "3C:7C:3F": "ASUSTek Computer (Router)",
    "20:A1:71": "Amazon (Echo / Alexa)",
    "50:07:C3": "Amazon (Echo / Alexa)",
    "58:E4:88": "Amazon (Echo / Alexa)",
    "FC:E9:D8": "Amazon (Echo / Alexa)",
    "EC:B5:FA": "Philips Lighting (Hue Bridge)",
    "BC:07:1D": "Arcadyan / Altice (Router Gateway)",
    "90:CA:FA": "Google / Android TV (Chromecast)",
    "BC:24:11": "Proxmox Server Solutions (Home Assistant)",
    "E8:AA:CB": "Samsung Electronics",
    "60:74:F4": "Samsung Electronics",
    "E8:50:8B": "Samsung Electronics",
    "DC:8E:95": "Woan Technology (SwitchBot)",
    "A4:C1:38": "Woan Technology (SwitchBot)",
    "F4:CF:A2": "Woan Technology (SwitchBot)",
    "74:4D:BD": "Woan Technology (SwitchBot)",
    "8C:85:80": "Woan Technology (SwitchBot)",

    # =========================================================================
    # 1. SMART HOME & IOT
    # =========================================================================
    # Espressif Systems (ESP32, ESP8266, módulos IoT de domótica)
    "18:FE:34": "Espressif Systems (ESP32 / ESP8266)",
    "24:0A:C4": "Espressif Systems (ESP32 / ESP8266)",
    "24:62:AB": "Espressif Systems (ESP32 / ESP8266)",
    "24:6F:28": "Espressif Systems (ESP32 / ESP8266)",
    "24:B2:DE": "Espressif Systems (ESP32 / ESP8266)",
    "24:DC:C3": "Espressif Systems (ESP32 / ESP8266)",
    "2C:F4:32": "Espressif Systems (ESP32 / ESP8266)",
    "30:AE:A4": "Espressif Systems (ESP32 / ESP8266)",
    "30:C6:F7": "Espressif Systems (ESP32 / ESP8266)",
    "30:C9:22": "Espressif Systems (ESP32 / ESP8266)",
    "34:85:18": "Espressif Systems (ESP32 / ESP8266)",
    "34:86:5D": "Espressif Systems (ESP32 / ESP8266)",
    "34:94:54": "Espressif Systems (ESP32 / ESP8266)",
    "34:B7:DA": "Espressif Systems (ESP32 / ESP8266)",
    "3C:61:05": "Espressif Systems (ESP32 / ESP8266)",
    "3C:71:BF": "Espressif Systems (ESP32 / ESP8266)",
    "3C:84:27": "Espressif Systems (ESP32 / ESP8266)",
    "40:22:D8": "Espressif Systems (ESP32 / ESP8266)",
    "40:4C:CA": "Espressif Systems (ESP32 / ESP8266)",
    "44:17:93": "Espressif Systems (ESP32 / ESP8266)",
    "48:27:E2": "Espressif Systems (ESP32 / ESP8266)",
    "48:3F:DA": "Espressif Systems (ESP32 / ESP8266)",
    "48:55:19": "Espressif Systems (ESP32 / ESP8266)",
    "48:E7:29": "Espressif Systems (ESP32 / ESP8266)",
    "4C:11:AE": "Espressif Systems (ESP32 / ESP8266)",
    "50:02:91": "Espressif Systems (ESP32 / ESP8266)",
    "54:32:04": "Espressif Systems (ESP32 / ESP8266)",
    "54:43:B2": "Espressif Systems (ESP32 / ESP8266)",
    "54:5A:A6": "Espressif Systems (ESP32 / ESP8266)",
    "58:BF:25": "Espressif Systems (ESP32 / ESP8266)",
    "5C:CF:7F": "Espressif Systems (ESP32 / ESP8266)",
    "60:01:94": "Espressif Systems (ESP32 / ESP8266)",
    "60:55:F9": "Espressif Systems (ESP32 / ESP8266)",
    "68:B6:B3": "Espressif Systems (ESP32 / ESP8266)",
    "68:C6:3A": "Espressif Systems (ESP32 / ESP8266)",
    "70:03:9F": "Espressif Systems (ESP32 / ESP8266)",
    "70:B8:F6": "Espressif Systems (ESP32 / ESP8266)",
    "78:21:84": "Espressif Systems (ESP32 / ESP8266)",
    "78:E3:6D": "Espressif Systems (ESP32 / ESP8266)",
    "7C:87:CE": "Espressif Systems (ESP32 / ESP8266)",
    "7C:9E:BD": "Espressif Systems (ESP32 / ESP8266)",
    "7C:DF:A1": "Espressif Systems (ESP32 / ESP8266)",
    "80:7D:3A": "Espressif Systems (ESP32 / ESP8266)",
    "84:0D:8E": "Espressif Systems (ESP32 / ESP8266)",
    "84:CC:A8": "Espressif Systems (ESP32 / ESP8266)",
    "84:F3:EB": "Espressif Systems (ESP32 / ESP8266)",
    "8C:4B:14": "Espressif Systems (ESP32 / ESP8266)",
    "8C:4F:00": "Espressif Systems (ESP32 / ESP8266)",
    "8C:AA:B5": "Espressif Systems (ESP32 / ESP8266)",
    "90:38:0C": "Espressif Systems (ESP32 / ESP8266)",
    "94:3C:C6": "Espressif Systems (ESP32 / ESP8266)",
    "94:B5:55": "Espressif Systems (ESP32 / ESP8266)",
    "94:B9:7E": "Espressif Systems (ESP32 / ESP8266)",
    "98:CD:AC": "Espressif Systems (ESP32 / ESP8266)",
    "A0:20:A6": "Espressif Systems (ESP32 / ESP8266)",
    "A0:76:4E": "Espressif Systems (ESP32 / ESP8266)",
    "A0:B7:65": "Espressif Systems (ESP32 / ESP8266)",
    "A4:7B:9D": "Espressif Systems (ESP32 / ESP8266)",
    "A4:C1:38": "Espressif Systems (ESP32 / ESP8266)",
    "A4:CF:12": "Espressif Systems (ESP32 / ESP8266)",
    "AC:0B:FB": "Espressif Systems (ESP32 / ESP8266)",
    "AC:15:18": "Espressif Systems (ESP32 / ESP8266)",
    "AC:67:B2": "Espressif Systems (ESP32 / ESP8266)",
    "B0:A7:32": "Espressif Systems (ESP32 / ESP8266)",
    "B4:E6:2D": "Espressif Systems (ESP32 / ESP8266)",
    "B8:D6:1A": "Espressif Systems (ESP32 / ESP8266)",
    "BC:DD:C2": "Espressif Systems (ESP32 / ESP8266)",
    "C0:49:EF": "Espressif Systems (ESP32 / ESP8266)",
    "C4:4F:33": "Espressif Systems (ESP32 / ESP8266)",
    "C4:DE:E2": "Espressif Systems (ESP32 / ESP8266)",
    "C8:2E:18": "Espressif Systems (ESP32 / ESP8266)",
    "C8:C9:A3": "Espressif Systems (ESP32 / ESP8266)",
    "CC:50:E3": "Espressif Systems (ESP32 / ESP8266)",
    "D8:A0:1D": "Espressif Systems (ESP32 / ESP8266)",
    "D8:BC:38": "Espressif Systems (ESP32 / ESP8266)",
    "DC:4F:22": "Espressif Systems (ESP32 / ESP8266)",
    "DC:54:75": "Espressif Systems (ESP32 / ESP8266)",
    "E0:5A:1B": "Espressif Systems (ESP32 / ESP8266)",
    "E0:98:06": "Espressif Systems (ESP32 / ESP8266)",
    "E8:31:CD": "Espressif Systems (ESP32 / ESP8266)",
    "E8:6B:EA": "Espressif Systems (ESP32 / ESP8266)",
    "E8:DB:84": "Espressif Systems (ESP32 / ESP8266)",
    "EC:62:60": "Espressif Systems (ESP32 / ESP8266)",
    "EC:64:C9": "Espressif Systems (ESP32 / ESP8266)",
    "EC:94:CB": "Espressif Systems (ESP32 / ESP8266)",
    "EC:DA:3B": "Espressif Systems (ESP32 / ESP8266)",
    "F0:08:D1": "Espressif Systems (ESP32 / ESP8266)",
    "F4:CF:A2": "Espressif Systems (ESP32 / ESP8266)",

    # Tuya Smart (Smart Life / Dispositivos Matter / Domótica Inteligente)
    "00:33:7A": "Tuya Smart Inc.",
    "10:5A:17": "Tuya Smart Inc.",
    "10:D5:61": "Tuya Smart Inc.",
    "18:69:D8": "Tuya Smart Inc.",
    "18:DE:50": "Tuya Smart Inc.",
    "1C:90:FF": "Tuya Smart Inc.",
    "38:1F:8D": "Tuya Smart Inc.",
    "50:8A:06": "Tuya Smart Inc.",
    "50:8B:B9": "Tuya Smart Inc.",
    "68:57:2D": "Tuya Smart Inc.",
    "7C:F6:66": "Tuya Smart Inc.",
    "84:E3:42": "Tuya Smart Inc.",
    "A0:92:08": "Tuya Smart Inc.",
    "D0:56:E3": "Tuya Smart Inc.",

    # Shelly / Allterco
    "84:00:EC": "Shelly Europe Ltd (Allterco)",

    # Sonoff / Coolkit / Itead
    "44:5D:5E": "Sonoff / Coolkit Technology",

    # IKEA of Sweden (Trådfri / Dirigera)
    "68:EC:8A": "IKEA of Sweden (Trådfri)",

    # Aqara / Lumi United
    "18:C2:3C": "Aqara / Lumi United",
    "54:EF:44": "Aqara / Lumi United",

    # Philips Lighting / Signify (Hue Bridge / Luminárias)
    "00:17:88": "Philips Lighting (Hue Bridge)",
    "C4:29:96": "Signify B.V. (Philips Hue)",
    "EC:B5:FA": "Philips Lighting (Hue Bridge)",

    # Netatmo
    "70:EE:50": "Netatmo (Smart Weather / Thermostat)",

    # Tado
    "EC:E5:12": "Tado GmbH (Smart Thermostat)",

    # Withings
    "00:24:E4": "Withings Health",
    "A4:7E:FA": "Withings Health",

    # Ring (Video Doorbells, Security Cams)
    "00:B4:63": "Ring LLC (Amazon)",
    "18:7F:88": "Ring LLC (Amazon)",
    "24:2B:D6": "Ring LLC (Amazon)",
    "34:3E:A4": "Ring LLC (Amazon)",
    "50:E4:67": "Ring LLC (Amazon)",
    "54:E0:19": "Ring LLC (Amazon)",
    "5C:47:5E": "Ring LLC (Amazon)",
    "64:9A:63": "Ring LLC (Amazon)",
    "90:48:6C": "Ring LLC (Amazon)",
    "9C:76:13": "Ring LLC (Amazon)",
    "AC:9F:C3": "Ring LLC (Amazon)",
    "C4:DB:AD": "Ring LLC (Amazon)",
    "CC:3B:FB": "Ring LLC (Amazon)",

    # Blink (Security Cameras)
    "3C:A0:70": "Blink (Amazon)",
    "70:AD:43": "Blink (Amazon)",
    "74:13:48": "Blink (Amazon)",
    "74:AB:93": "Blink (Amazon)",
    "C8:19:D8": "Blink (Amazon)",
    "F0:74:C1": "Blink (Amazon)",

    # Wyze Labs
    "2C:AA:8E": "Wyze Labs",
    "7C:78:B2": "Wyze Labs",
    "80:48:2C": "Wyze Labs",
    "A4:DA:22": "Wyze Labs",
    "D0:3F:27": "Wyze Labs",
    "F0:C8:8B": "Wyze Labs",

    # =========================================================================
    # 2. ROUTERS, SWITCHES & REDES
    # =========================================================================
    # Ubiquiti / UniFi
    "00:15:6D": "Ubiquiti Networks (UniFi)",
    "00:27:22": "Ubiquiti Networks (UniFi)",
    "04:18:D6": "Ubiquiti Networks (UniFi)",
    "0C:EA:14": "Ubiquiti Networks (UniFi)",
    "18:E8:29": "Ubiquiti Networks (UniFi)",
    "24:5A:4C": "Ubiquiti Networks (UniFi)",
    "24:A4:3C": "Ubiquiti Networks (UniFi)",
    "28:70:4E": "Ubiquiti Networks (UniFi)",
    "44:D9:E7": "Ubiquiti Networks (UniFi)",
    "60:22:32": "Ubiquiti Networks (UniFi)",
    "68:72:51": "Ubiquiti Networks (UniFi)",
    "74:83:C2": "Ubiquiti Networks (UniFi)",
    "78:45:58": "Ubiquiti Networks (UniFi)",
    "80:2A:A8": "Ubiquiti Networks (UniFi)",
    "B4:FB:E4": "Ubiquiti Networks (UniFi)",
    "DC:9F:DB": "Ubiquiti Networks (UniFi)",
    "E0:63:DA": "Ubiquiti Networks (UniFi)",
    "F0:9F:C2": "Ubiquiti Networks (UniFi)",

    # MikroTik (RouterBOARD)
    "00:0C:42": "MikroTik (RouterBOARD)",
    "08:55:31": "MikroTik (RouterBOARD)",
    "18:FD:74": "MikroTik (RouterBOARD)",
    "2C:C8:1B": "MikroTik (RouterBOARD)",
    "48:8F:5A": "MikroTik (RouterBOARD)",
    "48:A9:8A": "MikroTik (RouterBOARD)",
    "4C:5E:0C": "MikroTik (RouterBOARD)",
    "64:D1:54": "MikroTik (RouterBOARD)",
    "6C:3B:6B": "MikroTik (RouterBOARD)",
    "74:4D:28": "MikroTik (RouterBOARD)",
    "78:9A:18": "MikroTik (RouterBOARD)",
    "B8:69:F4": "MikroTik (RouterBOARD)",
    "C4:AD:34": "MikroTik (RouterBOARD)",
    "CC:2D:E0": "MikroTik (RouterBOARD)",
    "D4:CA:6D": "MikroTik (RouterBOARD)",
    "E4:8D:8C": "MikroTik (RouterBOARD)",

    # TP-Link
    "00:0A:EB": "TP-Link Corporation",
    "00:14:78": "TP-Link Corporation",
    "00:19:E0": "TP-Link Corporation",
    "00:21:27": "TP-Link Corporation",
    "00:23:CD": "TP-Link Corporation",
    "00:25:86": "TP-Link Corporation",
    "00:27:19": "TP-Link Corporation",
    "10:FE:ED": "TP-Link Corporation",
    "14:75:90": "TP-Link Corporation",
    "14:CF:92": "TP-Link Corporation",
    "14:EB:B6": "TP-Link Corporation",
    "1C:3B:F3": "TP-Link Corporation",
    "20:0C:C8": "TP-Link Corporation",
    "30:DE:4B": "TP-Link Corporation",
    "50:C7:BF": "TP-Link Corporation",
    "54:AF:97": "TP-Link Corporation",
    "54:C8:0F": "TP-Link Corporation",
    "60:32:B1": "TP-Link Corporation",
    "70:4F:57": "TP-Link Corporation",
    "74:05:A5": "TP-Link Corporation",
    "74:DA:88": "TP-Link Corporation",
    "84:16:F9": "TP-Link Corporation",
    "90:F6:52": "TP-Link Corporation",
    "98:DA:C4": "TP-Link Corporation",
    "A4:2B:B0": "TP-Link Corporation",
    "B0:95:75": "TP-Link Corporation",
    "C0:C9:E3": "TP-Link Corporation",
    "CC:32:E5": "TP-Link Corporation",
    "D8:0D:17": "TP-Link Corporation",
    "E8:48:B8": "TP-Link Corporation",
    "EC:08:6B": "TP-Link Corporation",
    "F4:F2:6D": "TP-Link Corporation",

    # Netgear
    "00:09:5B": "Netgear Inc.",
    "00:0F:B5": "Netgear Inc.",
    "00:14:6C": "Netgear Inc.",
    "00:14:D1": "Netgear Inc.",
    "00:18:4D": "Netgear Inc.",
    "00:1B:2F": "Netgear Inc.",
    "00:1E:2A": "Netgear Inc.",
    "00:1F:33": "Netgear Inc.",
    "00:22:3F": "Netgear Inc.",
    "00:24:B2": "Netgear Inc.",
    "00:26:F2": "Netgear Inc.",
    "04:A1:51": "Netgear Inc.",
    "08:02:8E": "Netgear Inc.",
    "08:36:C9": "Netgear Inc.",
    "10:0C:6B": "Netgear Inc.",
    "10:DA:43": "Netgear Inc.",
    "14:59:C0": "Netgear Inc.",
    "20:4E:7F": "Netgear Inc.",
    "20:E5:2A": "Netgear Inc.",
    "28:80:88": "Netgear Inc.",
    "28:C6:8E": "Netgear Inc.",
    "30:46:9A": "Netgear Inc.",
    "38:94:ED": "Netgear Inc.",
    "44:A5:6E": "Netgear Inc.",
    "4C:60:DE": "Netgear Inc.",
    "50:6A:03": "Netgear Inc.",
    "6C:B0:CE": "Netgear Inc.",
    "78:D2:94": "Netgear Inc.",
    "80:37:73": "Netgear Inc.",
    "84:1B:5E": "Netgear Inc.",
    "9C:3D:CF": "Netgear Inc.",
    "A0:04:60": "Netgear Inc.",
    "A0:63:91": "Netgear Inc.",
    "B0:7F:B9": "Netgear Inc.",
    "B0:B9:8A": "Netgear Inc.",
    "C0:3F:0E": "Netgear Inc.",
    "C4:04:15": "Netgear Inc.",
    "C4:3D:C7": "Netgear Inc.",
    "CC:40:D0": "Netgear Inc.",
    "E0:46:9A": "Netgear Inc.",
    "E4:F4:C6": "Netgear Inc.",

    # AVM (Fritz!Box)
    "00:04:0E": "AVM GmbH (Fritz!Box)",
    "00:15:0C": "AVM GmbH (Fritz!Box)",
    "00:1A:4F": "AVM GmbH (Fritz!Box)",
    "00:1C:4A": "AVM GmbH (Fritz!Box)",
    "00:1F:3F": "AVM GmbH (Fritz!Box)",
    "00:24:FE": "AVM GmbH (Fritz!Box)",
    "08:96:D7": "AVM GmbH (Fritz!Box)",
    "24:65:11": "AVM GmbH (Fritz!Box)",
    "34:31:C4": "AVM GmbH (Fritz!Box)",
    "34:81:C4": "AVM GmbH (Fritz!Box)",
    "9C:C7:A6": "AVM GmbH (Fritz!Box)",
    "BC:05:43": "AVM GmbH (Fritz!Box)",
    "C0:25:06": "AVM GmbH (Fritz!Box)",

    # Synology (NAS & Routers)
    "00:11:32": "Synology Inc. (NAS/Router)",
    "90:09:D0": "Synology Inc. (NAS/Router)",

    # QNAP (NAS / ICP Electronics)
    "00:08:9B": "QNAP Systems (ICP Electronics)",
    "24:5E:BE": "QNAP Systems",
    "E8:43:B6": "QNAP Systems",

    # ASUS (Routers de rede)
    "04:92:26": "ASUSTek Computer (Router)",
    "08:60:6E": "ASUSTek Computer (Router)",
    "10:7B:44": "ASUSTek Computer (Router)",
    "10:BF:48": "ASUSTek Computer (Router)",
    "10:C3:7B": "ASUSTek Computer (Router)",
    "14:DD:A9": "ASUSTek Computer (Router)",
    "18:31:BF": "ASUSTek Computer (Router)",
    "1C:87:2C": "ASUSTek Computer (Router)",
    "20:CF:30": "ASUSTek Computer (Router)",
    "24:4B:FE": "ASUSTek Computer (Router)",
    "2C:4D:54": "ASUSTek Computer (Router)",
    "2C:FD:A1": "ASUSTek Computer (Router)",
    "30:5A:3A": "ASUSTek Computer (Router)",
    "30:85:A9": "ASUSTek Computer (Router)",
    "34:97:F6": "ASUSTek Computer (Router)",
    "38:D5:47": "ASUSTek Computer (Router)",
    "3C:7C:3F": "ASUSTek Computer (Router)",
    "40:16:7E": "ASUSTek Computer (Router)",
    "40:16:9F": "ASUSTek Computer (Router)",
    "50:46:5D": "ASUSTek Computer (Router)",
    "54:A0:50": "ASUSTek Computer (Router)",
    "60:45:CB": "ASUSTek Computer (Router)",
    "70:8B:CD": "ASUSTek Computer (Router)",
    "AC:9E:17": "ASUSTek Computer (Router)",
    "BC:EE:7B": "ASUSTek Computer (Router)",

    # D-Link
    "00:05:5D": "D-Link Corporation",
    "00:0D:88": "D-Link Corporation",
    "00:0F:3D": "D-Link Corporation",
    "00:11:95": "D-Link Corporation",
    "00:13:46": "D-Link Corporation",
    "00:15:E9": "D-Link Corporation",
    "00:17:9A": "D-Link Corporation",
    "00:19:5B": "D-Link Corporation",
    "00:1B:11": "D-Link Corporation",
    "00:1C:F0": "D-Link Corporation",
    "00:1E:58": "D-Link Corporation",
    "00:21:91": "D-Link Corporation",
    "00:22:B0": "D-Link Corporation",
    "00:24:01": "D-Link Corporation",
    "00:26:5A": "D-Link Corporation",
    "14:D6:4D": "D-Link Corporation",
    "1C:7E:E5": "D-Link Corporation",
    "28:10:7B": "D-Link Corporation",
    "34:08:04": "D-Link Corporation",
    "70:62:B8": "D-Link Corporation",
    "78:54:2E": "D-Link Corporation",
    "84:C9:B2": "D-Link Corporation",
    "90:94:E4": "D-Link Corporation",
    "A0:F3:C1": "D-Link Corporation",
    "B0:C5:54": "D-Link Corporation",
    "C0:A0:BB": "D-Link Corporation",
    "CC:B2:55": "D-Link Corporation",
    "E4:6F:13": "D-Link Corporation",
    "F0:7D:68": "D-Link Corporation",

    # Linksys
    "00:04:5A": "Linksys",
    "00:06:25": "Linksys",
    "00:0C:41": "Linksys",
    "00:0E:2E": "Linksys",
    "00:0E:35": "Linksys",
    "00:0F:66": "Linksys",
    "00:12:17": "Linksys",
    "00:13:10": "Linksys",
    "00:14:BF": "Linksys",
    "00:16:B6": "Linksys",
    "00:18:39": "Linksys",
    "00:18:F8": "Linksys",
    "00:1A:70": "Linksys",
    "00:1C:10": "Linksys",
    "00:1D:7E": "Linksys",
    "00:1E:E5": "Linksys",
    "00:21:29": "Linksys",
    "00:22:6B": "Linksys",
    "00:23:69": "Linksys",
    "00:25:9E": "Linksys",
    "20:AA:4B": "Linksys",
    "68:7F:74": "Linksys",
    "C4:41:1E": "Linksys",

    # Cisco Systems
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:43": "Cisco Systems",
    "00:01:96": "Cisco Systems",
    "00:01:97": "Cisco Systems",
    "00:01:C7": "Cisco Systems",
    "00:01:C9": "Cisco Systems",
    "00:02:16": "Cisco Systems",
    "00:02:17": "Cisco Systems",
    "00:02:4A": "Cisco Systems",
    "00:02:4B": "Cisco Systems",
    "00:02:7D": "Cisco Systems",
    "00:02:7E": "Cisco Systems",
    "00:02:B9": "Cisco Systems",
    "00:02:BA": "Cisco Systems",
    "00:04:4D": "Cisco Systems",
    "00:05:31": "Cisco Systems",
    "00:05:32": "Cisco Systems",
    "00:05:5E": "Cisco Systems",
    "00:05:73": "Cisco Systems",
    "00:05:9A": "Cisco Systems",
    "00:06:52": "Cisco Systems",
    "00:06:53": "Cisco Systems",
    "00:07:0D": "Cisco Systems",
    "00:07:0E": "Cisco Systems",
    "00:07:4F": "Cisco Systems",
    "00:07:50": "Cisco Systems",
    "00:07:7D": "Cisco Systems",
    "00:07:84": "Cisco Systems",
    "00:07:85": "Cisco Systems",
    "00:07:B3": "Cisco Systems",
    "00:07:B4": "Cisco Systems",
    "00:08:20": "Cisco Systems",
    "00:08:21": "Cisco Systems",
    "00:08:7C": "Cisco Systems",
    "00:08:7D": "Cisco Systems",
    "00:08:A3": "Cisco Systems",
    "00:08:A4": "Cisco Systems",
    "00:08:E2": "Cisco Systems",
    "00:08:E3": "Cisco Systems",

    # DrayTek (Vigor Routers)
    "00:1D:AA": "DrayTek Corp. (Vigor Router)",
    "00:50:7F": "DrayTek Corp. (Vigor Router)",

    # Sagemcom (Operadoras MEO / NOS / Vodafone / Orange)
    "00:0E:59": "Sagemcom Broadband (Router)",
    "00:15:56": "Sagemcom Broadband (Router)",
    "00:19:4B": "Sagemcom Broadband (Router)",
    "00:1B:BF": "Sagemcom Broadband (Router)",
    "00:1D:6A": "Sagemcom Broadband (Router)",
    "00:1F:95": "Sagemcom Broadband (Router)",
    "00:23:48": "Sagemcom Broadband (Router)",
    "00:25:69": "Sagemcom Broadband (Router)",
    "00:37:B7": "Sagemcom Broadband (Router)",
    "00:60:4C": "Sagemcom Broadband (Router)",
    "34:8A:AE": "Sagemcom Broadband (Router)",
    "68:15:90": "Sagemcom Broadband (Router)",
    "70:54:F5": "Sagemcom Broadband (Router)",
    "98:1E:19": "Sagemcom Broadband (Router)",
    "E4:C0:E2": "Sagemcom Broadband (Router)",
    "E8:33:81": "Sagemcom Broadband (Router)",

    # Altice Labs (MEO FiberGateway / PT Inovação)
    "00:0F:F2": "Altice Labs (FiberGateway)",
    "00:19:70": "Altice Labs (FiberGateway)",

    # Arcadyan (Gateways Vodafone / NOS / MEO)
    "00:12:BF": "Arcadyan Technology (Router Gateway)",
    "00:1A:2A": "Arcadyan Technology (Router Gateway)",
    "00:26:4D": "Arcadyan Technology (Router Gateway)",
    "08:86:3B": "Arcadyan Technology (Router Gateway)",
    "14:5B:D1": "Arcadyan Technology (Router Gateway)",
    "18:82:8C": "Arcadyan Technology (Router Gateway)",
    "1C:B0:44": "Arcadyan Technology (Router Gateway)",
    "28:28:5D": "Arcadyan Technology (Router Gateway)",
    "44:32:C8": "Arcadyan Technology (Router Gateway)",
    "4C:14:A3": "Arcadyan Technology (Router Gateway)",
    "50:7E:5D": "Arcadyan Technology (Router Gateway)",
    "54:67:51": "Arcadyan Technology (Router Gateway)",
    "74:31:70": "Arcadyan Technology (Router Gateway)",
    "7C:4C:A5": "Arcadyan Technology (Router Gateway)",
    "84:A4:23": "Arcadyan Technology (Router Gateway)",
    "88:25:2C": "Arcadyan Technology (Router Gateway)",
    "88:E3:AB": "Arcadyan Technology (Router Gateway)",
    "98:9D:5D": "Arcadyan Technology (Router Gateway)",
    "A8:D3:F7": "Arcadyan Technology (Router Gateway)",
    "B8:F8:53": "Arcadyan Technology (Router Gateway)",
    "BC:14:01": "Arcadyan Technology (Router Gateway)",
    "C8:99:B2": "Arcadyan Technology (Router Gateway)",
    "D8:FB:5E": "Arcadyan Technology (Router Gateway)",
    "E4:BE:ED": "Arcadyan Technology (Router Gateway)",
    "F0:82:61": "Arcadyan Technology (Router Gateway)",

    # Technicolor / Vantiva (Gateways / ONT / STB)
    "00:90:D0": "Technicolor / Vantiva (Gateway)",
    "1C:E4:DD": "Technicolor / Vantiva (Gateway)",
    "2C:30:1A": "Technicolor / Vantiva (Gateway)",
    "38:F1:8F": "Technicolor / Vantiva (Gateway)",
    "88:F7:C7": "Technicolor / Vantiva (Gateway)",
    "A0:82:1F": "Technicolor / Vantiva (Gateway)",
    "F0:16:28": "Technicolor / Vantiva (Gateway)",

    # =========================================================================
    # 3. ÁUDIO & STREAMING
    # =========================================================================
    # Sonos (Smart Speakers / Som Multiroom)
    "00:0E:58": "Sonos, Inc.",
    "5C:AA:FD": "Sonos, Inc.",
    "78:28:CA": "Sonos, Inc.",
    "94:9F:3E": "Sonos, Inc.",

    # Bose Corporation
    "00:0C:8A": "Bose Corporation",
    "04:52:C7": "Bose Corporation",
    "08:DF:1F": "Bose Corporation",
    "2C:41:A1": "Bose Corporation",
    "4C:87:5D": "Bose Corporation",
    "60:AB:D2": "Bose Corporation",
    "78:2B:64": "Bose Corporation",
    "AC:BF:71": "Bose Corporation",
    "BC:87:FA": "Bose Corporation",
    "C8:7B:23": "Bose Corporation",

    # Yamaha Corporation
    "00:A0:DE": "Yamaha Corporation (Audio)",
    "AC:44:F2": "Yamaha Corporation (Audio)",
    "F4:D5:80": "Yamaha Corporation (Audio)",

    # Denon / Marantz (D&M Holdings)
    "00:05:CD": "Denon / Marantz (D&M Holdings)",
    "00:06:78": "Denon / Marantz (D&M Holdings)",
    "8C:A9:6F": "Denon / Marantz (D&M Holdings)",

    # Roku, Inc. (Streaming Sticks, Boxes & Roku TVs)
    "00:0D:4B": "Roku, Inc. (Streaming Player)",
    "08:05:81": "Roku, Inc. (Streaming Player)",
    "10:59:32": "Roku, Inc. (Streaming Player)",
    "20:EF:BD": "Roku, Inc. (Streaming Player)",
    "34:5E:08": "Roku, Inc. (Streaming Player)",
    "7C:67:AB": "Roku, Inc. (Streaming Player)",
    "84:EA:ED": "Roku, Inc. (Streaming Player)",
    "88:DE:A9": "Roku, Inc. (Streaming Player)",
    "8C:49:62": "Roku, Inc. (Streaming Player)",
    "B8:3E:59": "Roku, Inc. (Streaming Player)",
    "BC:D7:D4": "Roku, Inc. (Streaming Player)",

    # LG Electronics (Smart TVs WebOS)
    "A8:23:FE": "LG Electronics",
    "00:1F:6B": "LG Electronics",
    "58:FD:B1": "LG Electronics",
    "64:99:5D": "LG Electronics",
    "74:40:BE": "LG Electronics",

    # =========================================================================
    # 4. CONSOLAS & GAMING
    # =========================================================================
    # Sony Interactive Entertainment (PlayStation 4, PlayStation 5)
    "00:04:1F": "Sony Interactive (PlayStation)",
    "00:13:15": "Sony Interactive (PlayStation)",
    "00:15:C1": "Sony Interactive (PlayStation)",
    "00:19:C5": "Sony Interactive (PlayStation)",
    "00:1D:0D": "Sony Interactive (PlayStation)",
    "00:1F:A7": "Sony Interactive (PlayStation)",
    "70:9E:29": "Sony Interactive (PlayStation)",
    "FC:0F:E6": "Sony Interactive (PlayStation)",

    # Microsoft Corporation (Xbox One, Xbox Series X/S)
    "00:0D:3A": "Microsoft Corporation (Xbox / Surface)",
    "00:12:5A": "Microsoft Corporation (Xbox / Surface)",
    "00:15:5D": "Microsoft Corporation (Xbox / Surface)",
    "00:17:FA": "Microsoft Corporation (Xbox / Surface)",
    "00:1D:D8": "Microsoft Corporation (Xbox / Surface)",
    "00:22:48": "Microsoft Corporation (Xbox / Surface)",
    "00:25:AE": "Microsoft Corporation (Xbox / Surface)",
    "00:50:F2": "Microsoft Corporation (Xbox / Surface)",
    "28:18:78": "Microsoft Corporation (Xbox / Surface)",
    "30:59:B7": "Microsoft Corporation (Xbox / Surface)",
    "48:A4:72": "Microsoft Corporation (Xbox / Surface)",
    "50:1A:C5": "Microsoft Corporation (Xbox / Surface)",
    "58:82:A8": "Microsoft Corporation (Xbox / Surface)",
    "60:45:BD": "Microsoft Corporation (Xbox / Surface)",
    "70:66:55": "Microsoft Corporation (Xbox / Surface)",
    "7C:1E:52": "Microsoft Corporation (Xbox / Surface)",
    "7C:ED:8D": "Microsoft Corporation (Xbox / Surface)",
    "98:5F:D3": "Microsoft Corporation (Xbox / Surface)",
    "A0:85:FC": "Microsoft Corporation (Xbox / Surface)",
    "B4:AE:2B": "Microsoft Corporation (Xbox / Surface)",
    "C4:9D:ED": "Microsoft Corporation (Xbox / Surface)",
    "DC:B4:C4": "Microsoft Corporation (Xbox / Surface)",
    "E4:A4:71": "Microsoft Corporation (Xbox / Surface)",

    # Nintendo Co., Ltd. (Switch / Wii U)
    "00:09:BF": "Nintendo Co., Ltd. (Switch)",
    "00:16:56": "Nintendo Co., Ltd. (Switch)",
    "00:17:AB": "Nintendo Co., Ltd. (Switch)",
    "00:19:1D": "Nintendo Co., Ltd. (Switch)",
    "00:19:FD": "Nintendo Co., Ltd. (Switch)",
    "00:1B:7A": "Nintendo Co., Ltd. (Switch)",
    "00:1B:EA": "Nintendo Co., Ltd. (Switch)",
    "00:1D:BC": "Nintendo Co., Ltd. (Switch)",
    "00:1E:35": "Nintendo Co., Ltd. (Switch)",
    "00:1F:32": "Nintendo Co., Ltd. (Switch)",
    "00:21:47": "Nintendo Co., Ltd. (Switch)",
    "00:21:BD": "Nintendo Co., Ltd. (Switch)",
    "00:22:4C": "Nintendo Co., Ltd. (Switch)",
    "00:22:D7": "Nintendo Co., Ltd. (Switch)",
    "00:23:31": "Nintendo Co., Ltd. (Switch)",
    "00:23:CC": "Nintendo Co., Ltd. (Switch)",
    "00:24:1E": "Nintendo Co., Ltd. (Switch)",
    "00:24:44": "Nintendo Co., Ltd. (Switch)",
    "00:24:F3": "Nintendo Co., Ltd. (Switch)",
    "00:25:A0": "Nintendo Co., Ltd. (Switch)",
    "00:26:59": "Nintendo Co., Ltd. (Switch)",
    "04:03:D6": "Nintendo Co., Ltd. (Switch)",
    "18:2A:7B": "Nintendo Co., Ltd. (Switch)",
    "2C:10:C1": "Nintendo Co., Ltd. (Switch)",
    "34:AF:2C": "Nintendo Co., Ltd. (Switch)",
    "40:D2:8A": "Nintendo Co., Ltd. (Switch)",
    "58:2F:40": "Nintendo Co., Ltd. (Switch)",
    "70:48:0F": "Nintendo Co., Ltd. (Switch)",
    "78:A2:A0": "Nintendo Co., Ltd. (Switch)",
    "7C:BB:8A": "Nintendo Co., Ltd. (Switch)",
    "8C:56:C5": "Nintendo Co., Ltd. (Switch)",
    "94:58:CB": "Nintendo Co., Ltd. (Switch)",
    "98:B6:E9": "Nintendo Co., Ltd. (Switch)",
    "A4:C0:E1": "Nintendo Co., Ltd. (Switch)",
    "B8:8A:EC": "Nintendo Co., Ltd. (Switch)",
    "CC:9E:00": "Nintendo Co., Ltd. (Switch)",
    "D8:6B:F7": "Nintendo Co., Ltd. (Switch)",
    "E0:0C:7F": "Nintendo Co., Ltd. (Switch)",
    "E0:E7:51": "Nintendo Co., Ltd. (Switch)",
    "E8:4E:CE": "Nintendo Co., Ltd. (Switch)",

    # Valve Corporation (Steam Deck)
    "E0:31:9E": "Valve Corporation (Steam Deck)",

    # =========================================================================
    # 5. COMPUTADORES & IMPRESSORAS
    # =========================================================================
    # Apple (MacBook, iMac, Mac Mini, iPad, iPhone)
    "28:CF:E9": "Apple, Inc.",
    "40:98:AD": "Apple, Inc.",
    "60:03:08": "Apple, Inc.",
    "64:B0:A6": "Apple, Inc.",
    "78:7B:8A": "Apple, Inc.",
    "80:A9:97": "Apple, Inc.",
    "9C:20:7B": "Apple, Inc.",
    "A4:83:E7": "Apple, Inc.",
    "A8:66:7F": "Apple, Inc.",
    "AC:DE:48": "Apple, Inc.",
    "B0:34:95": "Apple, Inc.",
    "BC:9F:EF": "Apple, Inc.",
    "C8:69:CD": "Apple, Inc.",
    "D8:00:4D": "Apple, Inc.",
    "DC:A9:04": "Apple, Inc.",
    "E4:E4:AB": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "F4:34:F0": "Apple, Inc.",
    "F4:F9:51": "Apple, Inc.",
    "F8:FF:C2": "Apple, Inc.",

    # Lenovo (ThinkPad / IdeaPad / Legion)
    "00:59:07": "Lenovo Mobile",
    "14:9F:E8": "Lenovo",
    "20:76:93": "Lenovo",
    "24:69:A5": "Lenovo",
    "28:39:5E": "Lenovo",
    "30:10:E4": "Lenovo",
    "54:EE:75": "Lenovo",
    "60:99:D1": "Lenovo",
    "6C:6A:77": "Lenovo",
    "88:70:8C": "Lenovo",
    "A4:8C:DB": "Lenovo",
    "C8:5B:76": "Lenovo",
    "D8:CE:3A": "Lenovo",
    "E0:2B:E9": "Lenovo",

    # Dell Inc.
    "00:14:22": "Dell Inc.",
    "00:1A:A0": "Dell Inc.",
    "00:1E:4F": "Dell Inc.",
    "00:21:70": "Dell Inc.",
    "00:22:19": "Dell Inc.",
    "00:24:E8": "Dell Inc.",
    "00:26:B9": "Dell Inc.",
    "18:03:73": "Dell Inc.",
    "18:66:DA": "Dell Inc.",
    "24:B6:FD": "Dell Inc.",
    "34:17:EB": "Dell Inc.",
    "44:A8:42": "Dell Inc.",
    "74:86:7A": "Dell Inc.",
    "84:7B:EB": "Dell Inc.",
    "90:B1:1C": "Dell Inc.",
    "B8:2A:72": "Dell Inc.",
    "C8:F7:50": "Dell Inc.",
    "D4:BE:D9": "Dell Inc.",
    "E4:54:E8": "Dell Inc.",
    "F8:DB:88": "Dell Inc.",

    # HP Inc / Hewlett Packard (PCs, Laptops, Impressoras)
    "00:01:E6": "HP Inc.",
    "00:08:02": "HP Inc.",
    "00:0B:CD": "HP Inc.",
    "00:0E:7F": "HP Inc.",
    "00:11:0A": "HP Inc.",
    "00:14:38": "HP Inc.",
    "00:17:A4": "HP Inc.",
    "00:1A:4B": "HP Inc.",
    "00:1E:0B": "HP Inc.",
    "00:21:5A": "HP Inc.",
    "00:23:7D": "HP Inc.",
    "00:24:81": "HP Inc.",
    "00:25:B3": "HP Inc.",
    "10:60:4B": "HP Inc.",
    "18:60:24": "HP Inc.",
    "2C:27:D7": "HP Inc.",
    "3C:D9:2B": "HP Inc.",
    "70:5A:0F": "HP Inc.",
    "80:C1:6E": "HP Inc.",
    "A4:5D:36": "HP Inc.",
    "C8:CB:B8": "HP Inc.",
    "D8:9D:67": "HP Inc.",

    # Micro-Star INTL (MSI)
    "00:0C:76": "Micro-Star INTL (MSI)",
    "00:16:17": "Micro-Star INTL (MSI)",
    "00:19:DB": "Micro-Star INTL (MSI)",
    "00:1D:92": "Micro-Star INTL (MSI)",
    "00:21:85": "Micro-Star INTL (MSI)",
    "00:24:21": "Micro-Star INTL (MSI)",
    "00:26:18": "Micro-Star INTL (MSI)",
    "04:D4:C4": "Micro-Star INTL (MSI)",
    "2C:F0:5D": "Micro-Star INTL (MSI)",
    "30:9C:23": "Micro-Star INTL (MSI)",

    # Acer
    "00:01:24": "Acer Incorporated",
    "00:07:95": "Acer Incorporated",
    "00:16:D3": "Acer Incorporated",
    "00:1A:6B": "Acer Incorporated",
    "00:1F:16": "Acer Incorporated",
    "00:23:5A": "Acer Incorporated",
    "00:26:2D": "Acer Incorporated",
    "04:76:6E": "Acer Incorporated",
    "18:06:FF": "Acer Incorporated",
    "20:6A:8A": "Acer Incorporated",
    "2C:60:0C": "Acer Incorporated",
    "44:1C:A8": "Acer Incorporated",
    "54:49:61": "Acer Incorporated",
    "68:94:23": "Acer Incorporated",
    "88:AE:1D": "Acer Incorporated",
    "90:FB:A6": "Acer Incorporated",
    "C0:38:96": "Acer Incorporated",

    # Intel Corporate (Placas de Rede Wi-Fi/Ethernet para PCs e Laptops)
    "00:1E:67": "Intel Corporate",
    "00:21:5C": "Intel Corporate",
    "34:E6:D7": "Intel Corporate",
    "70:1C:E8": "Intel Corporate",
    "80:86:F2": "Intel Corporate",
    "A4:4C:C8": "Intel Corporate",

    # Raspberry Pi Foundation (Trading)
    "28:CD:C1": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
    "D8:3A:DD": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",

    # Impressoras (Brother, Epson, Canon)
    "00:80:77": "Brother Industries",
    "00:1B:A9": "Brother Industries",
    "30:05:5C": "Brother Industries",
    "00:00:48": "Seiko Epson Corp.",
    "00:26:AB": "Seiko Epson Corp.",
    "44:D8:78": "Seiko Epson Corp.",
    "00:1A:80": "Canon Inc.",
    "00:00:85": "Canon Inc.",
    "18:0C:AC": "Canon Inc.",

    # Virtualização / Servidores
    "00:0C:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",

    # =========================================================================
    # 6. MOBILE & WEARABLES
    # =========================================================================
    # Samsung Electronics (Galaxy Phones, Tablets, Smart Watches, Smart TVs)
    "00:12:47": "Samsung Electronics",
    "00:15:99": "Samsung Electronics",
    "00:16:32": "Samsung Electronics",
    "00:17:C9": "Samsung Electronics",
    "00:18:AF": "Samsung Electronics",
    "00:1A:8A": "Samsung Electronics",
    "00:1D:25": "Samsung Electronics",
    "00:21:19": "Samsung Electronics",
    "00:23:D7": "Samsung Electronics",
    "00:24:54": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "24:4B:03": "Samsung Electronics",
    "30:07:4D": "Samsung Electronics",
    "44:91:60": "Samsung Electronics",
    "54:92:BE": "Samsung Electronics",
    "60:74:F4": "Samsung Electronics",
    "B4:07:F9": "Samsung Electronics",
    "CC:07:AB": "Samsung Electronics",
    "D0:03:DF": "Samsung Electronics",
    "E4:E0:C5": "Samsung Electronics",

    # Xiaomi / POCO / Redmi
    "04:CF:8C": "Xiaomi Communications",
    "50:EC:50": "Xiaomi Communications",
    "64:90:C1": "Xiaomi Communications",
    "78:11:DC": "Xiaomi Communications",
    "AC:C1:EE": "Xiaomi Communications",

    # OnePlus / OPPO
    "24:7C:F2": "OnePlus / OPPO",
    "28:80:23": "OnePlus / OPPO",
    "50:80:4A": "OnePlus / OPPO",
    "74:D2:1D": "OnePlus / OPPO",
    "98:09:CF": "OnePlus / OPPO",
    "9C:2E:A1": "OnePlus / OPPO",
    "B0:EE:45": "OnePlus / OPPO",
    "BC:66:41": "OnePlus / OPPO",
    "E4:07:48": "OnePlus / OPPO",
    "F8:A2:D6": "OnePlus / OPPO",

    # Motorola Mobility
    "00:04:56": "Motorola Mobility",
    "00:0A:28": "Motorola Mobility",
    "00:0C:E5": "Motorola Mobility",
    "00:0F:9F": "Motorola Mobility",
    "00:11:1A": "Motorola Mobility",
    "00:12:25": "Motorola Mobility",
    "00:14:9A": "Motorola Mobility",
    "00:17:EE": "Motorola Mobility",
    "00:1A:DB": "Motorola Mobility",
    "00:24:92": "Motorola Mobility",
    "14:30:04": "Motorola Mobility",
    "24:DA:33": "Motorola Mobility",
    "3C:57:D5": "Motorola Mobility",
    "40:78:6A": "Motorola Mobility",
    "80:6C:1B": "Motorola Mobility",
    "98:3B:8F": "Motorola Mobility",
    "A4:70:D6": "Motorola Mobility",
    "CC:C3:EA": "Motorola Mobility",
    "E0:75:7D": "Motorola Mobility",
    "F8:F1:B6": "Motorola Mobility",

    # Huawei Technologies (Smartphones / Routers / Infra)
    "00:1E:10": "Huawei Technologies",
    "10:47:80": "Huawei Technologies",
    "24:69:68": "Huawei Technologies",
    "40:7C:16": "Huawei Technologies",
    "48:46:FB": "Huawei Technologies",
    "A4:71:74": "Huawei Technologies",
    "AC:C3:3A": "Huawei Technologies",
}

def normalize_mac(mac: str) -> str:
    """Standardizes MAC address format into 12-char lowercase and separated by colons."""
    if not mac:
        return ""
    clean = re.sub(r'[^a-fA-F0-9]', '', mac).lower()
    if len(clean) != 12:
        # Pad leading zeroes if components were single digit (like 4:7c:16...)
        parts = re.split(r'[:-]', mac)
        if len(parts) == 6:
            clean = "".join(p.zfill(2) for p in parts).lower()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return mac.lower()

def is_randomized_mac(mac: str) -> bool:
    """
    Returns True if the MAC address has the local administration bit set (private Wi-Fi address).
    In IEEE 802, if the 2nd least significant bit of the first octet is 1, it's locally administered (e.g. x2, x6, xA, xE).
    Used by iOS 'Private Address', Android 'Randomized MAC', and Windows 'Random Hardware Address'.
    """
    norm = normalize_mac(mac)
    if len(norm) >= 2:
        try:
            first_byte = int(norm[:2], 16)
            return bool(first_byte & 0x02)
        except ValueError:
            return False
    return False

def fetch_online_oui(mac: str) -> str:
    """Dynamically queries online IEEE OUI API to resolve uncataloged MAC addresses with fast timeout."""
    import urllib.request
    import json
    norm = normalize_mac(mac).upper()
    if not norm or len(norm) < 8:
        return ""
    prefix = norm[:8]
    clean_prefix = prefix.replace(":", "")
    try:
        req = urllib.request.Request(
            f"https://api.maclookup.app/v2/macs/{clean_prefix}",
            headers={"User-Agent": "NetPulse-Agent/2.0"}
        )
        with urllib.request.urlopen(req, timeout=1.8) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("success") and data.get("company"):
                    company = data.get("company").strip()
                    if company:
                        KNOWN_OUIS[prefix] = company
                        return company
    except Exception:
        pass
    return ""

def lookup_vendor(mac: str, allow_online: bool = True) -> str:
    """Finds the vendor name for a MAC address using OUI prefix matching, online API fallback, and random MAC detection."""
    norm = normalize_mac(mac).upper()
    if not norm or norm == "FF:FF:FF:FF:FF:FF":
        return "Broadcast"

    # Check 3-byte prefix (OUI)
    prefix_3 = norm[:8]
    if prefix_3 in KNOWN_OUIS:
        return KNOWN_OUIS[prefix_3]

    # Check if randomized / locally administered (iOS Private Address, Android Randomized)
    if is_randomized_mac(norm):
        return "Dispositivo Privado (MAC Aleatório / iOS / Android)"

    # Dynamic IEEE lookup fallback
    if allow_online:
        online_vendor = fetch_online_oui(norm)
        if online_vendor:
            return online_vendor

    return "Desconhecido"

def classify_device(ip: str, mac: str, hostname: str, vendor: str, open_ports: list = None, is_gateway: bool = False, custom_name: str = "") -> str:
    """
    Categorizes the device type based on network role, vendor, hostname, custom_name, and open ports.
    Available categories:
    - 'router': Router, Gateway, Switch, Access Point
    - 'mobile': Smartphone, Tablet (iPhone, iPad, Galaxy, etc.)
    - 'computer': Desktop, Laptop, MacBook, PC, Server
    - 'tv_media': Smart TV, Apple TV, Chromecast, Fire TV, Roku
    - 'iot': Smart Home, lâmpadas, tomadas, sensores, ESP32, Hue
    - 'gaming': PlayStation, Xbox, Nintendo Switch
    - 'printer': Impressoras de rede
    - 'unknown': Outros
    """
    h_lower = (hostname or "").lower()
    v_lower = (vendor or "").lower()
    n_lower = (custom_name or "").lower()
    combined = f"{h_lower} {v_lower} {n_lower}"
    open_ports = open_ports or []

    # 1. Network Gateway (Actual Primary Router)
    if is_gateway or (ip.endswith(".1") and not ("tapo" in combined or "camera" in combined or "cam" in combined or "câmara" in combined)):
        return "router"

    # 2. Cameras, Smart Home & IoT (Tapo, Kasa, Tuya, Reolink, RTSP/ONVIF, Smart Plugs, Sensors, Alexa, Home Assistant, SwitchBot)
    # MUST take precedence over vendor names like TP-Link, Xiaomi, etc. (TP-Link manufactures both routers and Tapo cameras/plugs!)
    is_smart_home_or_cam = (
        "switchbot" in combined or "switch-bot" in combined or "woan" in v_lower or
        "tapo" in combined or "kasa" in combined or "camera" in combined or "câmera" in combined or
        "câmara" in combined or "cam" in combined or "webcam" in combined or "ipcam" in combined or
        "reolink" in combined or "eufy" in combined or "ezviz" in combined or "hikvision" in combined or
        "dahua" in combined or "imou" in combined or "amcrest" in combined or "doorbell" in combined or
        "campainha" in combined or "intercom" in combined or "tomada" in combined or "smart plug" in combined or
        "plug" in combined or "lâmpada" in combined or "lampada" in combined or "bulb" in combined or
        "sensor" in combined or "home assistant" in combined or "hass" in combined or "aspirador" in combined or
        "vacuum" in combined or "robot" in combined or "amazon" in v_lower or "alexa" in combined or
        "echo" in combined or "espressif" in v_lower or "iot" in combined or "smarthome" in combined or
        "smart home" in combined or "domotica" in combined or "domótica" in combined or "hue" in combined or
        "philips lighting" in v_lower or "shelly" in combined or "allterco" in v_lower or
        "tasmota" in combined or "sonoff" in combined or "tuya" in combined or "ikea" in combined or
        "aqara" in combined or "ring" in combined or "blink" in combined or "wyze" in combined or
        "tado" in combined or "netatmo" in combined or "withings" in combined or
        1883 in open_ports or 8123 in open_ports or 554 in open_ports or 2020 in open_ports or 8554 in open_ports
    )
    if is_smart_home_or_cam:
        return "iot"

    # 3. Router / Gateway & Network Infrastructure (Switches, Access Points, Repeaters)
    if "router" in combined or "gateway" in combined or "access point" in combined or "switch" in combined or "deco" in combined or "altice" in v_lower or "sagemcom" in v_lower or "arcadyan" in v_lower or "tp-link" in v_lower or "ubiquiti" in v_lower or "netgear" in v_lower or "asus" in v_lower or "mikrotik" in v_lower or "fritz!box" in v_lower or "draytek" in v_lower or "cisco" in v_lower or "linksys" in v_lower or "d-link" in v_lower or "technicolor" in v_lower or "vantiva" in v_lower:
        return "router"

    # 2. Gaming Consoles
    if "playstation" in combined or "xbox" in combined or "nintendo" in combined or "steam deck" in combined or "nintendo switch" in combined or "switch oled" in combined:
        return "gaming"

    # 3. Printers
    if "printer" in combined or "impressora" in combined or "epson" in v_lower or "canon" in v_lower or "brother" in v_lower or "hp inc" in v_lower or 9100 in open_ports or 631 in open_ports:
        return "printer"

    # 4. Smart TV, Áudio & Media Streaming
    if "tv" in combined or "smart tv" in combined or "bravia" in combined or "webos" in combined or "chromecast" in combined or "firetv" in combined or "roku" in combined or "apple tv" in combined or "shield" in combined or "formuler" in combined or "aloys" in combined or "sonos" in combined or "bose" in combined or "yamaha" in combined or "denon" in combined or "marantz" in combined or 8001 in open_ports:
        return "tv_media"

    # 5. IoT & Smart Home (Home Assistant, Amazon Echo / Alexa, Espressif, Philips Hue, Shelly, Tuya, IKEA, Aqara, Ring, Wyze, Robot Vacuums)
    if "home assistant" in combined or "hass" in combined or "aspirador" in combined or "vacuum" in combined or "robot" in combined or "amazon" in v_lower or "alexa" in combined or "echo" in combined or "espressif" in v_lower or "iot" in combined or "hue" in combined or "philips lighting" in v_lower or "shelly" in combined or "allterco" in v_lower or "tasmota" in combined or "sonoff" in combined or "tuya" in combined or "ikea" in combined or "aqara" in combined or "ring" in combined or "blink" in combined or "wyze" in combined or "tado" in combined or "netatmo" in combined or "withings" in combined or 1883 in open_ports or 8123 in open_ports:
        return "iot"

    # 6. Mobile devices vs Computers (Apple, Samsung, etc.)
    if "iphone" in combined or "ipad" in combined:
        return "mobile"
    if "macbook" in combined or "mac-mini" in combined or "imac" in combined:
        return "computer"

    if "apple" in v_lower:
        return "mobile"

    if "samsung" in v_lower:
        if "tv" in combined:
            return "tv_media"
        return "mobile"

    if "xiaomi" in v_lower or "huawei" in v_lower or "oneplus" in v_lower or "oppo" in v_lower or "motorola" in v_lower:
        return "mobile"

    if "intel" in v_lower or "vmware" in v_lower or "synology" in v_lower or "qnap" in v_lower or "lenovo" in v_lower or "dell" in v_lower or "acer" in v_lower or "msi" in v_lower or "micro-star" in v_lower or "raspberry pi" in v_lower or "ixsystems" in v_lower or "truenas" in v_lower or "proxmox" in v_lower or "unraid" in combined or "castleserver" in combined or "server" in combined or 22 in open_ports or 3389 in open_ports or 445 in open_ports:
        return "computer"

    if is_randomized_mac(mac):
        return "mobile"

    return "unknown"
