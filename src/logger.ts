import bunyan from "bunyan";

export const logger = bunyan.createLogger({
  name: "voprf-server",
  streams: [
    {
      level: "debug",
      stream: process.stdout,
    },
    {
      type: "rotating-file",
      level: "info",
      path: `logs/voprf-server-debug.log`,
      period: "1d", // daily rotation
      count: 10, // keep 10 back copies
    },
    {
      type: "rotating-file",
      level: "error",
      path: `logs/voprf-server-error.log`,
      period: "1d", // daily rotation
      count: 10, // keep 10 back copies
    },
  ],
});
