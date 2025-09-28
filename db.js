const mqtt = require('mqtt');
const Database = require('better-sqlite3');
const { name } = require('ejs');

const userDb = new Database('test.db');
const sysDb = new Database('systeme.db');
// Connect to broker with clientId (and optional username/password)
const client = mqtt.connect('mqtt://localhost:1885', {
  clientId: 'db',
  username: 'db', // optional
  password: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyI4bjJqeSI6eyJ4ejY5OCI6ZmFsc2UsInR5cGUiOiJTZXJ2aWNlIiwicm9sZSI6ImRCU2VydmljZSJ9LCJteXMybSI6OTA1NTUsInR5cGUiOiJTZXJ2aWNlIiwicm9sZSI6ImRCU2VydmljZSIsImlhdCI6MTc1ODE1NjY1NX0._-mocEbDpv_nBgEi3fGxM904FfKbkE9H3LGKpY8E5Pc', // optional
});
function cleanTopic(Topic) {
  return Topic.replace(/\+\/?/g, "");
}
function getTopicsByRole(role) {
  const stmt = userDb.prepare(`
    SELECT topic, type, action
    FROM MQTT_Topics
    WHERE role = ?
  `);

  const rows = stmt.all(role);
  // Structure output
  const topics = {
    sub_topics: {},
    pub_topics: {},
    pubsub_topics: {}
  };

  rows.forEach(row => {
    let category;
    if (row.action === 'sub') {
      category = topics.sub_topics;
    } else if (row.action === 'pub') {
      category = topics.pub_topics;
    } else if (row.action === 'pub/sub') {
      category = topics.pubsub_topics;
    }

    if (!category[row.type]) {
      category[row.type] = [];
    }
    category[row.type].push(row.topic);
  });

  return topics;
}

// Topic to publish/subscribe (can include clientId if you want separate topics per device)
const topics = getTopicsByRole("dBService")
console.log(topics);
// When connected
client.on('connect', () => {
  console.log(`Connected to MQTT broker`);
//pubsub_topics
   // Subscribe to sub_topics
  for (const [type, arr] of Object.entries(topics.sub_topics)) {
    arr.forEach(el => {
      client.subscribe(el, (err) => {
        if (!err) {
          console.log(`📩 Subscribed to ${type}||topic:${el}`);
        } else {
          console.log(`❌ Subscribe failed to ${type}||topic:${el}`);
          console.error('❌ Subscribe error:', err);
        }
      });
    });
  }
  for (const [type, arr] of Object.entries(topics.pubsub_topics)) {
    arr.forEach(el => {
      client.subscribe(el, (err) => {
        if (!err) {
          console.log(`📩 Subscribed to ${type}||topic:${el}`);
        } else {
          console.log(`❌ Subscribe failed to ${type}||topic:${el}`);
          console.error('❌ Subscribe error:', err);
        }
      });
    });
  }
});
// When a message is received
client.on('message', (topic, data) => {
  // Split topic into parts
  const msg=data.toString();
  const parts = topic.split('/');
  const equipment_id = parts[1];
  const type = parts[0]; // example: Sensors, Parameters, Status, Consigne

  console.log("📩 Received:", topic, "->", msg.toString());

  switch (type) {
    case "Sensors":
      const sensorType = parts[2];
      // Now check length to differentiate
      if (parts.length === 6) {
        const level=parts[3];
        const x=parts[4];
        const y=parts[5];
        try {
        const stmt = sysDb.prepare(`
          UPDATE Sensors
          SET value = ?
          WHERE id = (
            SELECT sp.sensor_id
            FROM SensorPosition sp
            JOIN Sensors s ON s.id = sp.sensor_id
            WHERE s.equipment_id = ? 
              AND s.type = ? 
              AND sp.level = ? 
              AND sp.x = ? 
              AND sp.y = ?
          )
        `);

        stmt.run(msg, equipment_id, sensorType, level, x, y);
      } catch (err) {
        console.error("Failed to update sensor value:", err.message);
      }

      } else if (parts.length === 4) {
        const level = parts[3];
        try {
          const stmt = sysDb.prepare(`
            UPDATE SenserType_Averages_per_Level
            SET value = ?, date = CURRENT_TIMESTAMP
            WHERE equipment_id = ? AND sensor_type = ? AND level = ?
          `);

          stmt.run(msg, equipment_id, sensorType, level);
        } catch (err) {
          console.error("Failed to update SenserType_Averages_per_Level:", err);
        }


      } else if (parts.length === 3) {
        //Update the sensers avrage values
        try {
          const stmt = sysDb.prepare(`
            UPDATE EquipmentSensorTypes
            SET value = ?
            WHERE equipment_id = ? AND sensor_type = ?
          `);

          stmt.run(msg, equipment_id, sensorType);
        } catch (err) {
          console.error("Failed to update EquipmentSensorTypes:", err);
        }
      }
      break;

    case "Parameters":
      const param_name = parts[2];
      const change_by1 = parts[3];
      try {
        const stmt = sysDb.prepare(`
          UPDATE EquipmentParameters
          SET value = ?, last_change_by = ?, last_update = CURRENT_TIMESTAMP
          WHERE equipment_id = ? AND name = ?
        `);

        stmt.run(msg, change_by1, equipment_id, param_name);
        client.publish(topics.pub_topics.NotificationParameter+`/${param_name}`,`${param_name}:${msg} for ${equipment_id} set by ${change_by1}`,{qos:2})
      } catch (err) {
        console.error("Failed to update EquipmentParameters:", err);
      }

      break;

    case "Status":
        const status_name = parts[2];
        const change_by2 = parts[3];
        try {
          const stmt = sysDb.prepare(`
            UPDATE EquipmentStatus
            SET value = ?, last_change_by = ?, last_update = CURRENT_TIMESTAMP
            WHERE equipment_id = ? AND name = ?
          `);

          stmt.run(msg, change_by2, equipment_id, status_name);
        } catch (err) {
          console.error("Failed to update EquipmentStatus:", err);
        }

      break;

    case "Consigne":
      const sensorTypeC = parts[2];
      const consignName = parts[3];
      data=JSON.parse(data);
      if(parts.length==7){
        const change_by = parts[6];
        const sensorId = parts[5];   // 👈 you provide sensor_id directly

        console.log(sensorTypeC);

        try {
          // 1️⃣ Get the old value + unit before update
          const oldRow = sysDb.prepare(`
            SELECT 
                c.value AS old_value,
                st.unit,
                p.level,
                p.x,
                p.y
            FROM SensorConsigns c
            JOIN Sensors s 
                ON c.sensor_id = s.id
            JOIN SensorTypes st 
                ON s.type = st.type
            JOIN SensorPosition p 
                ON c.sensor_id = p.sensor_id
            WHERE c.sensor_id = ? 
              AND c.name = ?;
          `).get(sensorId, consignName);

          const oldValue = oldRow ? oldRow.old_value : null;
          const unit = oldRow ? oldRow.unit : null;
          const position = {
            level: oldRow ? oldRow.level : null,
            x: oldRow ? oldRow.x : null,
            y: oldRow ? oldRow.y : null
          }
          // 2️⃣ Update the SensorConsigns value
          const stmt = sysDb.prepare(`
            UPDATE SensorConsigns
            SET value = ?,
                description = ?,           
                last_change_by = ?,
                last_update = CURRENT_TIMESTAMP
            WHERE sensor_id = ? AND name = ?;
          `);

          stmt.run(
            data.value,
            data.description,   // operator reason
            change_by,
            sensorId,
            consignName
          );

          // 3️⃣ Build detail string for user log view
          const technicalDetail = `${sensorTypeC} ${consignName} Consigne (SensorID:${sensorId}) changed from ${oldValue}${unit ? " " + unit : ""} to ${data.value}${unit ? " " + unit : ""} in ${equipment_id}`;

          // 4️⃣ Insert into system_log with SCADA/ML JSON
          const logStmt = sysDb.prepare(`
            INSERT INTO system_log (
              name,
              message,
              detail,
              json_data,
              type,
              sender,
              log_date,
              read_permession
            )
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
          `);

          logStmt.run(
            "Consign updated",
            `${technicalDetail}`,                        
            `${data.description || "No reason provided"}`,  
            JSON.stringify({
              event: "consign_update",
              timestamp: new Date().toISOString(),
              sensor: {
                id: sensorId,
                type: sensorTypeC,
                position : position || null,
                name: consignName,
                unit: unit || null
              },
              change: {
                old_value: oldValue,
                new_value: data.value,
                unit: unit || null,
                reason: data.description || null,
                changed_by: change_by
              }
            }),
            "EVENT",                                         // SCADA log type
            change_by,                                       // sender
            "admin,operator"                                 // permissions
          );
          client.publish(topics.pub_topics.NotificationConsigne+`/${sensorTypeC.replace(/_.*/, "")}`,`${sensorTypeC} ${consignName} Consigne (Level:${position.level} ,X:${position.x} ,Y:${position.y}) changed from ${oldValue}${unit ? " " + unit : ""} to ${data.value}${unit ? " " + unit : ""} in ${equipment_id}`,{qos:2})
        } catch (err) {
          console.error("Failed to update SensorConsigns and log system action:", err);
        }

      }
      break;
    case 'Actions':
      if(!msg) return;
      const action = parts[1];
      const actionID = parts[2];
      const source = parts[3];
      const datajson = JSON.parse(data);
      const status = datajson.status;
      const duration = datajson?.duration;
      const time = datajson.time;
      let notification;
      const JSONobj = { ...datajson };
      delete JSONobj.status;
      delete JSONobj.duration;
      delete JSONobj.time;
      try {
        if (["Completed", "Error", "Canceled"].includes(status)) {
          const row = sysDb.prepare(`SELECT time FROM Actions WHERE id = ?`).get(actionID);
          const start_time = row ? row.time : null;
          const insertHist = sysDb.prepare(`
            INSERT INTO Actions_History (action_id, action_code, source, JSON, status, start_time, end_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `);
          insertHist.run(
            actionID,                // action_id
            action,                  // action_code
            source,
            JSON.stringify(JSONobj),
            status,
            start_time,
            time                     // end_time
          );
          setTimeout(() => {
            console.log('fg,lmdfkgekrpto')
            const delStmt = sysDb.prepare(`DELETE FROM Actions WHERE id = ?`);
            delStmt.run(actionID);
            client.publish(topic, "", { qos: 2 , retain: false});
          }, 30000);
        }
        if (status === "Started") {
          // First insert with time
          const stmt = sysDb.prepare(`
            INSERT OR IGNORE INTO Actions (id, action_code, status, source, JSON, duration, time)
            VALUES (?, ?, ?, ?, ?, ?, ?);
          `);

          stmt.run(
            actionID,
            action,
            status,
            source,
            JSON.stringify(JSONobj),
            duration,
            time // set start time now
          );
        } else {
          // Update status/details only, don't touch time
          const stmt = sysDb.prepare(`
            UPDATE Actions
            SET status = ?, source = ?, JSON = ?, duration = ?
            WHERE id = ?
          `);

          stmt.run(
            status,
            source,
            JSON.stringify(JSONobj),
            duration,
            actionID
          );
        }
        if(action ==="Grain_Transfert"){
          notification=`${action} ${status} from ${datajson.from} to ${datajson.to} by ${source}`;
        } 
        else if(action === "Dust_Aspiration"){
          notification=`${action} ${status} at ${datajson.equipment_id} by ${source}`;
        }
        console.log(topics.pub_topics.NotificationAction[0])
        client.publish(
          topics.pub_topics.NotificationAction[0],
          `(action code:${actionID}) ${notification}`,
          { qos: 1 },
          (err) => {
            if (err) {
              console.error("❌ Failed to publish action notification:", err);
              throw err; // or handle gracefully
            }
            console.log("✅ Successfully published action notification to:", topics.pub_topics.NotificationAction);
          }
        );

      } catch (err) {
        console.error("Failed to update Actions:", err);
      }
      break;
    case 'Alarms':
      
      break;
    default:
      console.warn("⚠️ Unhandled topic:", topic);
      break;
  }
});


// Handle errors
client.on('error', (err) => {
  console.error('MQTT Error:', err);
});

function Set_event(event,data){
  console.log(event)
  console.log(data)
  switch(event){
    case 'set_status':
        try {
          const oldRow = sysDb.prepare(`
            SELECT 
                c.value,
                st.unit
            FROM EquipmentSensorTypeConsigne c
            JOIN SensorTypes st 
                ON c.sensor_type = st.type
            WHERE c.equipment_id = ? 
              AND c.sensor_type = ? 
              AND c.name = ?;
          `).get(equipment_id, sensorTypeC, consignName);

          const technicalDetail = `${sensorTypeC} ${consignName} Consigne changed from ${oldValue}${unit ? " " + unit : ""} to ${data.value}${unit ? " " + unit : ""} in ${equipment_id}`;
          const stmt = sysDb.prepare(`
            UPDATE EquipmentStatus
            SET value = ?, last_change_by = ?, description = ?, last_update = CURRENT_TIMESTAMP
            WHERE equipment_id = ? AND name = ?
          `);

          stmt.run(data.value, data.sender, data.description, data.equipment_id,'OperatingStatus');
        } catch (err) {
          console.error("Failed to update EquipmentStatus:", err);
        }
      break;

    case "set_parameter":
      try {
        const stmt = sysDb.prepare(`
          UPDATE EquipmentParameters
          SET value = ?, last_change_by = ?, last_update = CURRENT_TIMESTAMP
          WHERE equipment_id = ? AND name = ?
        `);

        stmt.run(data.value, data.sender, data.equipment_id, data.name);
        const technicalDetail = ` ${data.name} changed from ${data.oldValue} to ${data.value} in ${data.equipment_id}`;
         const logStmt = sysDb.prepare(`
            INSERT INTO system_log (
              name,
              message,
              detail,
              extra_files,
              json_data,
              type,
              sender,
              log_date,
              read_permession
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
          logStmt.run(
            `${data.name} updated`,
            `${technicalDetail}`,                        
            `${data.description || "No reason provided"}`, 
            data?.files?.join(",") || null,
            JSON.stringify({
              event: "parameter_update",
              parameter: data.name,
              timestamp: data.time,
              equipment_id: data.equipment_id,
              change: {
                old_value: data.oldValue,
                new_value: data.value,
                reason: data.description || null,
                extra_files:data.files,
                changed_by: data.sender
              }
            }),
            "INFO",                                         // SCADA log type
            data.sender,                                       // sender
            data.time,
            "admin,operator"                                 // permissions
          );
          const payload = {
            value:data.value,
            date:data.time
          }
          console.log(`Parameters/${data.equipment_id}/${data.name}`,JSON.stringify(payload))
          client.publish(`Parameters/${data.equipment_id}/${data.name}`,JSON.stringify(payload),{qos:2,retain:true},(err)=>{
            if(err){
              console.error('Failed to publish Parameters',err);
            }
            console.log(`Publish scuess to Parameters/${data.equipment_id}/${data.name}`,JSON.stringify(payload))
          });
          client.publish(topics.pub_topics.NotificationParameter+`/${data.name}`,technicalDetail+ ` by ${data.sender}`,{qos:2})
      } catch (err) {
        console.error("Failed to update EquipmentParameters:", err);
      }
      break;
    
    case "set_consigne":
      console.log("db",data)
      try {
        const stmt = sysDb.prepare(`
          UPDATE EquipmentSensorTypeConsigne
          SET value = ?,
              last_change_by = ?,
              last_time_change = CURRENT_TIMESTAMP
          WHERE equipment_id = ?
            AND sensor_type = ?
            AND name = ?
        `);
        stmt.run(data.value, data.sender, data.equipment_id, data.sensor_type, data.name);
        const technicalDetail = `${data.sensor_type} ${data.name} Consigne changed from ${data.oldValue}${data.unit ? " " + data.unit : ""} to ${data.value}${data.unit ? " " + data.unit : ""} in ${data.equipment_id}`;
        const logStmt = sysDb.prepare(`
          INSERT INTO system_log (
            name,
            message,
            detail,
            extra_files,
            json_data,
            type,
            sender,
            log_date,
            read_permession
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        `);
        logStmt.run(
          "Consign updated",
          `${technicalDetail}`,                        
          `${data.description || "No reason provided"}`,  
          data?.files?.join(",") || null,
          JSON.stringify({
            event: "consign_update",
            timestamp: new Date().toISOString(),
            sensor: {
              type_of_average:"Total Average",
              type: data.sensor_type,
              name: data.name,
              unit: data.unit || null
            },
            change: {
              old_value: data.oldValue,
              new_value: data.value,
              reason: data.description || null,
              changed_by: data.sender
            }
          }),
          "INFO",                                         // SCADA log type
          data.sender,                                       // sender
          "admin,operator"                                 // permissions
        );
        console.log("⏰ Time's up! 5");
        const payload = {
          value: data.value,
          timestamp: data.time
        };
        client.publish(cleanTopic(topics.pub_topics.Consigne[0])+`${data.equipment_id}/${data.sensor_type}/${data.name}`,JSON.stringify(payload),{qos:2,retain:true},(err)=> {
          if(err) {
            return console.error('failed to publish consigne:',err.msg)
          }
          console.log("publish sucess of consigne",cleanTopic(topics.pub_topics.Consigne[0])+`${data.equipment_id}/${data.sensor_type}/${data.name}`,data.value)
        });
        client.publish(cleanTopic(topics.pub_topics.NotificationConsigne[0])+`${data.sensor_type.replace(/_.*/, "")}`,technicalDetail + ` by ${data.sender}`,{qos:2},(err)=> {
          if(err) {
            return console.error('failed to publish consigne notification:',err.msg)
          }
          console.log("publish sucess of consigne notification",cleanTopic(topics.pub_topics.Consigne[0])+`${data.equipment_id}/${data.sensor_type}/${data.name}`,technicalDetail + ` by ${data.sender}`)
        });
      } catch (err) {
        console.error("Failed to update EquipmentSensorTypeConsigne:", err);
      }
      break;
    
    case "set_consigneperlevel":
        console.log(data)
      try {
        const stmt = sysDb.prepare(`
          UPDATE SensorConsigns_per_level
          SET value = ?,
              last_change_by = ?,
              last_update = CURRENT_TIMESTAMP
          WHERE equipment_id = ?
            AND sensor_type = ?
            AND level = ?
            AND name = ?
        `);

        stmt.run(data.value, data.sender, data.equipment_id, data.sensor_type, data.level, data.name);
        const technicalDetail = `${data.sensor_type} ${data.name} Consigne (level:${data.level}) changed from ${data.oldValue}${data.unit ? " " + data.unit : ""} to ${data.value}${data.unit ? " " + data.unit : ""} in ${data.equipment_id}`;
        const logStmt = sysDb.prepare(`
          INSERT INTO system_log (
            name,
            message,
            detail,
            extra_files,
            json_data,
            type,
            sender,
            log_date,
            read_permession
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        `);
        logStmt.run(
          "Consign updated",
          `${technicalDetail}`,                        
          `${data.description || "No reason provided"}`,  
          data?.files?.join(",") || null,
          JSON.stringify({
            event: "consign_update",
            timestamp: new Date().toISOString(),
            sensor: {
              type_of_average:"Level Average",
              level: data.level,
              type: data.sensor_type,
              name: data.name,
              unit: data.unit || null
            },
            change: {
              old_value: data.oldValue,
              new_value: data.value,
              reason: data.description || null,
              changed_by: data.sender
            }
          }),
          "INFO",                                         // SCADA log type
          data.sender,                                       // sender
          "admin,operator"                                 // permissions
        );
        const payload = {
          value: data.value,
          timestamp: data.time
        };

        client.publish(topics.pub_topics.Consigne+`${data.equipment_id}/${data.sensor_type}/${data.name}/${data.level}`,JSON.stringify(payload),{qos:2,retain:true},(err)=> {
          if(err) {
            return console.error('failed to publish consigne:',err.msg)
          }
          console.log("Publish sucess of consigne per level ",topics.pub_topics.Consigne+`${data.equipment_id}/${data.sensor_type}/${data.name}/${data.level}`,data.value)
        });
        client.publish(topics.pub_topics.NotificationConsigne+`/${data.sensor_type.replace(/_.*/, "")}`,technicalDetail+` by ${data.sender}`,{qos:2})
      } catch (err) {
        console.error("Failed to update SensorConsigns_per_level:", err);
      }
      break;
  }
}

module.exports={
  Set_event
}
