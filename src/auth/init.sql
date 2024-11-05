CREATE USER 'auth_user'@'localhost' IDENTIFIED BY 'Aauth123'

CREATE DATABASE auth;

GRANT ALL PRIVILEGES auth.* TO 'auth_user'@'localhost';

USE auth

CREATE TABLE user (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

INSERT INTO USER (email, password) VALUES ('admin@email.com', 'Admin123')