#!/bin/bash
# SARDAR PATEL INSTITUTE OF TECHNOLOGY - DVWA LAB SETUP SCRIPT (KALI LINUX VM)

# NOTE: Run this script inside your Kali Linux Virtual Machine (VM).

echo "[*] Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "[*] Installing LAMP stack and tools..."
sudo apt install -y apache2 mariadb-server php php-mysqli php-xml php-gd php-mbstring git unzip

echo "[*] Starting and enabling Apache & MariaDB services..."
sudo systemctl enable --now apache2
sudo systemctl enable --now mariadb

echo "[*] Securing MariaDB installation..."
sudo mysql_secure_installation

echo "[*] Creating DVWA database and user..."
sudo mysql -u root -p <<EOF
CREATE DATABASE dvwa;
CREATE USER 'dvwauser'@'localhost' IDENTIFIED BY 'dvwapass';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwauser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
EOF

echo "[*] Downloading DVWA..."
cd /tmp
git clone https://github.com/digininja/DVWA.git
sudo mv DVWA /var/www/html/dvwa

echo "[*] Setting permissions and creating config file..."
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa
cd /var/www/html/dvwa/config
sudo cp config.inc.php.dist config.inc.php

echo "[*] Updating config.inc.php with database credentials..."
sudo sed -i "s/^\$_DVWA\['db_user'\].*/\$_DVWA['db_user'] = 'dvwauser';/" config.inc.php
sudo sed -i "s/^\$_DVWA\['db_password'\].*/\$_DVWA['db_password'] = 'dvwapass';/" config.inc.php
sudo sed -i "s/^\$_DVWA\['db_database'\].*/\$_DVWA['db_database'] = 'dvwa';/" config.inc.php

echo "[*] Enabling PHP mysqli module..."
sudo phpenmod mysqli

echo "[*] Restarting Apache service..."
sudo systemctl restart apache2

echo "[*] DVWA setup complete!"
echo "Open your browser and go to: http://127.0.0.1/dvwa/setup.php"
echo "Click 'Create / Reset Database' to complete the setup."
