create database mp3;

use mp3;

create table accounts (nick VARCHAR(32) NOT NULL PRIMARY KEY, password VARCHAR(16), level VARCHAR(9));

create table servers (name VARCHAR(32) NOT NULL PRIMARY KEY, password VARCHAR(16));

grant select,create,drop,delete,insert on mp3.* to mp3@localhost identified by 'opennap';
