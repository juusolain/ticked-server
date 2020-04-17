CREATE TABLE users (
    userid varchar(36) NOT NULL,
    username varchar(255) NOT NULL,
    password text,
    PRIMARY KEY (userid)
);

CREATE TABLE tasks (
    taskid varchar(36) NOT NULL, 
    userid varchar(36) NOT NULL, 
    listid varchar(36) NOT NULL, 
    name text, 
    description text, 
    alarm text, 
    PRIMARY KEY (taskid)
);

CREATE TABLE lists (
    listid varchar(36) NOT NULL,
    userid varchar(36) NOT NULL,
    name text,
    PRIMARY KEY (listid)
);