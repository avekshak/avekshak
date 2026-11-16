import { buildApp } from "./app.js";

const PORT = Number(process.env.API_PORT ?? 8000);

const app = buildApp();

app
  .listen({ port: PORT, host: "0.0.0.0" })
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });