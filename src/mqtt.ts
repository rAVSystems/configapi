import mqtt from "mqtt";

export const MQTT_URL = process.env.MQTT_URL || "mqtt://localhost:1883";

export const mqttClient = mqtt.connect(MQTT_URL, { clientId: "av-api", clean: true });

export function initMqtt(log: { info: (msg: string) => void; error: (obj: any, msg: string) => void }) {
  mqttClient.on("connect", () => log.info("MQTT connected"));
  mqttClient.on("error", (err) => log.error({ err }, "MQTT error"));
}
