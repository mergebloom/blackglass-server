import { configFromEnvironment } from "./config";
import { startService } from "./service";

const config = configFromEnvironment();
const service = startService(config);

console.log(`Control plane: ${service.controlOrigin}`);
console.log(`Sync data plane: ws://${service.dataHost}`);
console.log(`Database: ${config.databasePath}`);

async function shutdown(): Promise<void> {
  await service.stop();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
