import {
  afterAll,
  beforeAll,
  describe,
  expect,
  onTestFinished,
  test,
} from "vitest";
import { cojsonInternals } from "cojson";
import { Group } from "jazz-tools";
import { createJazzTestAccount } from "jazz-tools/testing";
import { WebhookTestServer } from "./http-server.js";
import { WebhookRegistry } from "../webhook.js";

const { setIncomingMessagesTimeBudget } = cojsonInternals;
// cojson's default, in SYNC_SCHEDULER_CONFIG
const defaultTimeBudget = 50;

describe("webhook registration under load", () => {
  // A budget below zero makes the sync queue yield after every message,
  // the way a starved CPU makes it overrun its budget.
  beforeAll(() => setIncomingMessagesTimeBudget(-1));
  afterAll(() => setIncomingMessagesTimeBudget(defaultTimeBudget));

  test(
    "register returns for a CoValue that exists nowhere",
    { timeout: 5_000 },
    async () => {
      const account = await createJazzTestAccount({
        isCurrentActiveAccount: true,
      });
      const webhookServer = new WebhookTestServer();
      await webhookServer.start();
      const registryState = WebhookRegistry.createRegistry(
        Group.create({ owner: account }),
      );
      const webhookRegistry = new WebhookRegistry(registryState, {
        baseDelayMs: 10,
      });
      webhookRegistry.start();

      onTestFinished(() => {
        webhookServer.close();
        webhookRegistry.shutdown();
      });

      const webhookId = await webhookRegistry.register(
        webhookServer.getUrl(),
        "co_zMissingEverywhere",
      );

      expect(registryState[webhookId]?.$isLoaded).toBe(true);
    },
  );
});
