BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "ACL" (
	"client_id"	TEXT NOT NULL,
	"topic"	TEXT NOT NULL,
	"rw"	TEXT NOT NULL,
	PRIMARY KEY("client_id","topic")
);
CREATE TABLE IF NOT EXISTS "Devices" (
	"device_id"	TEXT,
	"user_id"	INTEGER,
	"type"	TEXT NOT NULL,
	"status"	TEXT NOT NULL,
	"created_date"	TIMESTAM NOT NULL,
	PRIMARY KEY("device_id"),
	FOREIGN KEY("user_id") REFERENCES "Users"("id")
);
CREATE TABLE IF NOT EXISTS "Devices_Types" (
	"type"	TEXT,
	"description"	TEXT NOT NULL,
	PRIMARY KEY("type")
);
CREATE TABLE IF NOT EXISTS "MQTT" (
	"client_id"	TEXT,
	"device_id"	TEXT NOT NULL,
	"status"	TEXT NOT NULL,
	"last_seen"	TIMESTAMP,
	PRIMARY KEY("client_id"),
	FOREIGN KEY("client_id") REFERENCES "ACL"("client_id"),
	FOREIGN KEY("device_id") REFERENCES "Devices"("device_id")
);
CREATE TABLE IF NOT EXISTS "Tokens" (
	"id"	INTEGER,
	"device_id"	TEXT NOT NULL,
	"token"	TEXT NOT NULL UNIQUE,
	"created_date"	TIMESTAMP,
	"expire_date"	TIMESTAMP,
	PRIMARY KEY("id" AUTOINCREMENT),
	FOREIGN KEY("device_id") REFERENCES "Devices"("device_id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "Users" (
	"id"	INTEGER,
	"username"	TEXT NOT NULL UNIQUE,
	"password"	TEXT NOT NULL,
	"first_name"	TEXT NOT NULL,
	"last_name"	TEXT NOT NULL,
	"phone_number"	TEXT NOT NULL,
	"email"	TEXT NOT NULL,
	"profile_pic"	TEXT,
	"role"	TEXT NOT NULL,
	"status"	TEXT NOT NULL,
	"created_date"	INTEGER NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "Users_Roles" (
	"role"	TEXT,
	"description"	TEXT NOT NULL,
	PRIMARY KEY("role")
);
CREATE TABLE IF NOT EXISTS "Users_Status" (
	"status"	TEXT,
	"description"	TEXT NOT NULL,
	PRIMARY KEY("status")
);
COMMIT;
