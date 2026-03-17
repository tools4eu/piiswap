CREATE TABLE operators (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT,
    first_name TEXT,
    last_name TEXT,
    phone TEXT,
    created_at TEXT
);

INSERT INTO operators VALUES (1, 'john.doe', 'john.doe@acme-corp.example.com', 'John', 'Doe', '+1 555-0101', '2026-01-15 10:00:00');
INSERT INTO operators VALUES (2, 'jane.smith', 'jane.smith@demo-police.example.com', 'Jane', 'Smith', '+1 555-0102', '2026-02-01 14:30:00');

CREATE TABLE victims (
    id INTEGER PRIMARY KEY,
    operator_id INTEGER,
    hostname TEXT,
    ip_address TEXT,
    os TEXT,
    first_seen TEXT
);

INSERT INTO victims VALUES (1, 1, 'LAPTOP-JOHNDOE', '192.168.1.50', 'Windows 11', '2026-03-15 14:23:01');
INSERT INTO victims VALUES (2, 1, 'DESKTOP-JSMITH', '10.0.0.5', 'Windows 10', '2026-03-15 14:24:10');

CREATE TABLE config (
    key TEXT PRIMARY KEY,
    value TEXT
);

INSERT INTO config VALUES ('admin_password', 'SuperGeheim123!');
INSERT INTO config VALUES ('api_key', 'DEMO_KEY_a8f2k4m9x7p3q1w5e6r0t2y4u8i');
INSERT INTO config VALUES ('c2_domain', 'evil-c2.com');
