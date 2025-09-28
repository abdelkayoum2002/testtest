// Import better-sqlite3 and connect to database
const Database = require('better-sqlite3');
const userDb = new Database('test.db');
userDb.pragma('foreign_keys = ON');
const sysDb = new Database('systeme.db');
sysDb.pragma('foreign_keys = ON');

// ===================== Roles, Profiles, Devices =====================
console.time("Table creation time");
/*try {
    // Roles table - Stores different user roles with a unique name
    userDb.prepare(`
        CREATE TABLE IF NOT EXISTS roles (
            role_name TEXT PRIMARY KEY NOT NULL UNIQUE
        )
    `).run();

    // Profiles table - Stores user profiles, linked to a role, ensures name+surname uniqueness
    userDb.prepare(`
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            First_name TEXT NOT NULL,
            Second_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL ,
            password TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            UNIQUE (First_name, Second_name),
            FOREIGN KEY (role) REFERENCES roles(role_name)
        )
    `).run();
    // Devices table - Stores devices linked to a profile, each with unique MQTT client per profile
    userDb.prepare(`
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            profile_id INTEGER  UNIQUE NOT NULL,
            mqtt_client_id TEXT UNIQUE,
            status TEXT NOT NULL, -- References Status table
            FOREIGN KEY (profile_id) REFERENCES profiles(id),
            FOREIGN KEY (status) REFERENCES Status(name)
        )
    `).run();
        
    // Status table - Defines allowed device statuses
    userDb.prepare(`
        CREATE TABLE IF NOT EXISTS Status (
            name TEXT PRIMARY KEY NOT NULL UNIQUE, -- e.g., 'online', 'offline', 'error'
            description TEXT
        )
    `).run();
    userDb.prepare(`
        CREATE TABLE IF NOT EXISTS token_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            access_token TEXT,          -- unique ID of the access token
            refresh_token TEXT,         -- unique ID of the refresh token
            revoked_at DATETIME,        -- when the token was revoked
            revoked_by INTEGER,         -- profile who revoked it
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY (revoked_by) REFERENCES profiles(id) ON DELETE SET NULL
        )
    `).run();
    userDb.prepare(`
        CREATE TABLE IF NOT EXISTS mqtt_acl (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            topic_pattern TEXT NOT NULL,       -- e.g., silo/+/status
            action TEXT NOT NULL CHECK (action IN ('pub', 'sub', 'pub/sub')),
            role TEXT NOT NULL,
            FOREIGN KEY (role) REFERENCES roles(role_name)
                ON DELETE CASCADE
                ON UPDATE CASCADE
        )
    `).run();

/*



    // Table to store parameters specific to each actuator
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS ActuatorParam (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        actuator TEXT NOT NULL UNIQUE,
        param_name TEXT,
        param_value TEXT,
        description TEXT,
        FOREIGN KEY (actuator) REFERENCES Actuators(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table to store parameters specific to each sensor
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS SensorsParam (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        sensor TEXT NOT NULL UNIQUE,
        param_name TEXT,
        param_value TEXT,
        description TEXT,
        FOREIGN KEY (sensor) REFERENCES Sensors(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table storing the coordinates (position) of sensors in a matrix layout per level
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS SensorCoordinates (
        id INTEGER PRIMARY KEY UNIQUE NOT NULL,
        sensor TEXT,
        level INTEGER NOT NULL,
        matrix_row INTEGER NOT NULL,
        matrix_col INTEGER NOT NULL,
        is_center BOOLEAN DEFAULT 0,
        FOREIGN KEY (sensor) REFERENCES Sensors(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table listing all equipments with their types
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS Equipments (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        name TEXT NOT NULL UNIQUE,
        equipment_type TEXT NOT NULL,
        FOREIGN KEY (equipment_type) REFERENCES EquipmenTypes(type) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table defining the possible equipment types and their descriptions
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS EquipmenTypes (
        type TEXT PRIMARY KEY NOT NULL UNIQUE,
        description TEXT NOT NULL
        )
    `).run();

    // Table to store parameters for each equipment
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS EquipmentParams (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        equipment TEXT NOT NULL UNIQUE,
        param_name TEXT,
        param_value TEXT,
        description TEXT,
        FOREIGN KEY (equipment) REFERENCES Equipments(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table defining sensor types and related equipment
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS SensorTypes (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        name TEXT NOT NULL UNIQUE,
        equipment TEXT NOT NULL UNIQUE,
        unit TEXT,
        description TEXT NOT NULL,
        FOREIGN KEY (equipment) REFERENCES Equipments(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table listing all sensors with their types
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS Sensors (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        name TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL UNIQUE,
        FOREIGN KEY (type) REFERENCES SensorTypes(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table storing sensor readings with timestamps
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS SensorsReadings (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        sensor TEXT NOT NULL UNIQUE,
        value REAL,
        time TIMESTAMP,
        FOREIGN KEY (sensor) REFERENCES Sensors(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table defining actuator types and their descriptions
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS ActuatorTypes (
        name TEXT PRIMARY KEY NOT NULL UNIQUE,
        description TEXT NOT NULL
        )
    `).run();

    // Table listing all actuators with their type and equipment relation
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS Actuators (
        name TEXT PRIMARY KEY NOT NULL UNIQUE,
        type TEXT NOT NULL UNIQUE,
        equipment TEXT NOT NULL UNIQUE,
        FOREIGN KEY (type) REFERENCES ActuatorTypes(name) ON DELETE NO ACTION ON UPDATE NO ACTION,
        FOREIGN KEY (equipment) REFERENCES Equipments(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table storing actuator status (boolean) and timestamp
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS ActuatorStatus (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        actuator TEXT NOT NULL UNIQUE,
        status BOOLEAN NOT NULL,
        date TIMESTAMP,
        FOREIGN KEY (actuator) REFERENCES Actuators(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table storing parameters related to actuator status entries
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS ActuatorStatusParam (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        status_id INTEGER NOT NULL UNIQUE,
        param_name TEXT,
        param_value TEXT,
        FOREIGN KEY (status_id) REFERENCES ActuatorStatus(id) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table defining types of relations between equipments
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS RelationTypes (
        name TEXT PRIMARY KEY NOT NULL UNIQUE,
        description TEXT
        )
    `).run();

    // Table listing relations between equipments with relation type
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS Relations (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        type TEXT NOT NULL UNIQUE,
        source_equipment TEXT NOT NULL,
        target_equipment TEXT NOT NULL,
        FOREIGN KEY (type) REFERENCES RelationTypes(name) ON DELETE NO ACTION ON UPDATE NO ACTION,
        FOREIGN KEY (source_equipment) REFERENCES Equipments(name) ON DELETE NO ACTION ON UPDATE NO ACTION,
        FOREIGN KEY (target_equipment) REFERENCES Equipments(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table storing parameters for each relation
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS RelationParams (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        relation_id INTEGER NOT NULL,
        param_name TEXT NOT NULL,
        param_value TEXT NOT NULL,
        FOREIGN KEY (relation_id) REFERENCES Relations(id) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();

    // Table storing setpoints (consigne) for sensors with min/max allowed values
    sysDb.prepare(`
        CREATE TABLE IF NOT EXISTS SensorConsigne (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        sensor TEXT NOT NULL UNIQUE,
        max_value REAL NOT NULL,
        min_value REAL NOT NULL,
        FOREIGN KEY (sensor) REFERENCES Sensors(name) ON DELETE NO ACTION ON UPDATE NO ACTION
        )
    `).run();*/
   /* console.log("All tables created successfully.");
} catch (err) {
        console.error("❌ Error creating tables:", err.message);
}
console.timeEnd("Table creation time");*/

/*function systemInitialize(dbPath = 'system.db') {
    const db = new Database(dbPath);

    db.transaction(() => {
        // ===== STATUS =====
        const statuses = ['OK', 'Blocked'];
        const insertStatus = db.prepare("INSERT INTO Status (name) VALUES (?)");
        statuses.forEach(s => insertStatus.run(s));

        // ===== EQUIPMENT TYPES =====
        const equipmentTypes = [
            'Big Silo', 'Mini Silo', 'Elevator', 'Conveyor', 'Dust Filter', 'Two-Way Valve'
        ];
        const insertEquipType = db.prepare("INSERT INTO EquipmentTypes (name) VALUES (?)");
        equipmentTypes.forEach(t => insertEquipType.run(t));

        // ===== SENSOR TYPES =====
        const sensorTypes = ['Temperature', 'Humidity', 'CO2', 'Level'];
        const insertSensorType = db.prepare("INSERT INTO SensorTypes (name) VALUES (?)");
        sensorTypes.forEach(t => insertSensorType.run(t));

        // ===== ACTUATOR TYPES =====
        const actuatorTypes = ['Top Vane', 'Bottom Vane', 'Motor', 'Fan', 'Direction Control'];
        const insertActuatorType = db.prepare("INSERT INTO ActuatorTypes (name) VALUES (?)");
        actuatorTypes.forEach(t => insertActuatorType.run(t));

        const getTypeId = (table, name) => db.prepare(`SELECT id FROM ${table} WHERE name = ?`).get(name).id;
        const getStatusId = name => db.prepare("SELECT id FROM Status WHERE name = ?").get(name).id;

        const insertEquipment = db.prepare(
            "INSERT INTO Equipments (name, type_id, status_id) VALUES (?, ?, ?)"
        );
        const insertSensor = db.prepare(
            "INSERT INTO Sensors (equipment_id, type_id) VALUES (?, ?)"
        );
        const insertActuator = db.prepare(
            "INSERT INTO Actuators (equipment_id, type_id) VALUES (?, ?)"
        );
        const insertRelation = db.prepare(
            "INSERT INTO Relations (from_equipment_id, to_equipment_id) VALUES (?, ?)"
        );

        const statusOK = getStatusId('OK');

        // ===== CREATE EQUIPMENTS =====

        // Big Silos
        const silos = [];
        for (let i = 1; i <= 2; i++) {
            const id = insertEquipment.run(`Big Silo ${i}`, getTypeId('EquipmentTypes', 'Big Silo'), statusOK).lastInsertRowid;
            ['Temperature', 'Humidity', 'CO2', 'Level'].forEach(s => insertSensor.run(id, getTypeId('SensorTypes', s)));
            insertActuator.run(id, getTypeId('ActuatorTypes', 'Top Vane'));
            insertActuator.run(id, getTypeId('ActuatorTypes', 'Bottom Vane'));
            silos.push(id);
        }

        // Mini Silos
        const miniSilos = [];
        for (let i = 1; i <= 3; i++) {
            const id = insertEquipment.run(`Mini Silo ${i}`, getTypeId('EquipmentTypes', 'Mini Silo'), statusOK).lastInsertRowid;
            insertActuator.run(id, getTypeId('ActuatorTypes', 'Bottom Vane'));
            miniSilos.push(id);
        }

        // Elevator
        const elevator = insertEquipment.run(`Elevator`, getTypeId('EquipmentTypes', 'Elevator'), statusOK).lastInsertRowid;
        insertActuator.run(elevator, getTypeId('ActuatorTypes', 'Motor'));

        // Conveyors
        const conveyors = [];
        for (let i = 1; i <= 3; i++) {
            const id = insertEquipment.run(`Conveyor ${i}`, getTypeId('EquipmentTypes', 'Conveyor'), statusOK).lastInsertRowid;
            insertActuator.run(id, getTypeId('ActuatorTypes', 'Bottom Vane'));
            insertActuator.run(id, getTypeId('ActuatorTypes', 'Motor'));
            conveyors.push(id);

            // Dust filter for each conveyor
            const filterId = insertEquipment.run(`Dust Filter ${i}`, getTypeId('EquipmentTypes', 'Dust Filter'), statusOK).lastInsertRowid;
            insertActuator.run(filterId, getTypeId('ActuatorTypes', 'Fan'));
            insertRelation.run(id, filterId); // link conveyor → dust filter
        }

        // Two-Way Valves
        const valves = [];
        for (let i = 1; i <= 2; i++) {
            const id = insertEquipment.run(`Two-Way Valve ${i}`, getTypeId('EquipmentTypes', 'Two-Way Valve'), statusOK).lastInsertRowid;
            insertActuator.run(id, getTypeId('ActuatorTypes', 'Direction Control'));
            valves.push(id);
        }

        // ===== RELATIONS (FLOW) =====
        // Example: mini silos → bottom conveyor → elevator → top conveyor → silos
        insertRelation.run(miniSilos[0], conveyors[0]);
        insertRelation.run(miniSilos[1], conveyors[0]);
        insertRelation.run(conveyors[0], elevator);
        insertRelation.run(elevator, conveyors[1]);
        insertRelation.run(conveyors[1], silos[0]);
        insertRelation.run(conveyors[1], silos[1]);

        // Silos bottom → top conveyor
        insertRelation.run(silos[0], conveyors[2]);
        insertRelation.run(silos[1], conveyors[2]);

        // Top conveyor → valve 1
        insertRelation.run(conveyors[2], valves[0]);
        // Valve 1 → mini silo or elevator
        insertRelation.run(valves[0], miniSilos[2]);
        insertRelation.run(valves[0], elevator);

        // Valve 2 for top conveyor feeding silo 1 or 2
        insertRelation.run(conveyors[1], valves[1]);
        insertRelation.run(valves[1], silos[0]);
        insertRelation.run(valves[1], silos[1]);
    })();

    console.log("System initialized successfully!");
}

//systemInitialize();
*/
module.exports = {
    sysDb: sysDb,
    userDb: userDb
};

