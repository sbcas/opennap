create database mp3;

use mp3;

create table accounts (nick VARCHAR(15) NOT NULL PRIMARY KEY, password VARCHAR(16), level VARCHAR(9), email VARCHAR(64), created INT, lastseen INT);

create table servers (name VARCHAR(32) NOT NULL PRIMARY KEY, password VARCHAR(16));

grant update,select,create,drop,delete,insert on mp3.* to mp3@localhost identified by 'opennap';
