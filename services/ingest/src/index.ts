import { startSyslogUdp, startSyslogTcp } from "./connectors/syslog.js";
import { startWazuhConnector } from "./connectors/wazuh.js";
import { startAwsConnector } from "./connectors/aws.js";
import { startIngestWorker } from "./worker.js";

startIngestWorker();
startSyslogUdp();
startSyslogTcp();
startWazuhConnector();
startAwsConnector();
