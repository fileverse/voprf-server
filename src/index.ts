import { config } from "./config";

import app from "./app";
import { logger } from "./logger";

// Here you set the PORT and IP of the server
const port = config.PORT || 8001;

// Initialize VOPRF server and start the HTTP server
async function startServer() {
  try {
    // Initialize VOPRF server

    // Start the HTTP server
    app.listen(port, () =>
      logger.info(`🚀 Server ready on port ${port}`)
    );
  } catch (error) {
    logger.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();

export default app;
