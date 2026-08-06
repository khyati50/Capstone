-- MySQL Database Creation Script
CREATE DATABASE IF NOT EXISTS capstone_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- User creation & permission grants
CREATE USER IF NOT EXISTS 'capstone_user'@'localhost' IDENTIFIED BY 'CapstonePassword123!';
GRANT ALL PRIVILEGES ON capstone_db.* TO 'capstone_user'@'localhost';
FLUSH PRIVILEGES;

USE capstone_db;
