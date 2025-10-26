-- dvwa_mariadb_setup.sql
-- MariaDB / MySQL setup for DVWA
-- Run as: sudo mysql -u root -p < dvwa_mariadb_setup.sql

-- Remove existing DVWA user if present
DROP USER IF EXISTS 'dvwa'@'localhost';

-- Remove existing DVWA database if present (optional cleanup)
DROP DATABASE IF EXISTS `dvwa`;

-- Create the required DVWA database
CREATE DATABASE `dvwa`;

-- Create the dedicated DVWA user with the specified password
-- (password used below is: dvwapass)
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'password';

-- Grant the new user full privileges on the DVWA database
GRANT ALL PRIVILEGES ON `dvwa`.* TO 'dvwa'@'localhost';

-- Apply the privilege changes immediately
FLUSH PRIVILEGES;

-- End of script
