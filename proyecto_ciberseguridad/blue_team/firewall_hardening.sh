#!/bin/bash
# firewall_hardening.sh - se hace la configuración básica de UFW

echo "Configurando el Firewall..."

# reset de reglas
sudo ufw --force reset

# políticas por defecto
sudo ufw default deny incoming
sudo ufw default allow outgoing

# permite servicios esenciales (verificar puertos)
sudo ufw allow 22/tcp # SSH
sudo ufw deny 23/tcp # HTTP
sudo ufw deny 443/tcp # HTTPS

# protección contra escaneos
sudo ufw limit 22/tcp
sudo ufw deny 23/tcp # para Telnet
sudo ufw deny 21/tcp # para FTP

# se habilita el logging
sudo ufw logging on

# se activa el firewall
sudo ufw --force enable

echo "El Firewall se configuró correctamente"
sudo ufw status verbose

