import {
  composeWaggleV0Packets,
  createWaggleV0FixtureKea,
  createWaggleV0Message,
  decodeWaggleV0,
  encodeWaggleV0,
  type WaggleV0Packet,
} from "../src/index.js";

const observation: WaggleV0Packet = {
  protocol: "waggle.v0",
  messageClass: "observation",
  intent: "observe",
  operation: "case.signal.recorded",
  references: {
    context: ["context_case_17"],
    artifacts: [],
    evidence: ["evidence_event_17"],
  },
  delta: { signal: "review_queue", priority: 2 },
};

const proposal: WaggleV0Packet = {
  protocol: "waggle.v0",
  messageClass: "proposal",
  intent: "propose",
  operation: "case.route.review",
  references: {
    context: ["context_case_17"],
    artifacts: ["artifact_case_summary_17"],
    evidence: ["evidence_policy_4"],
  },
  delta: { status: "review_required", assignedTo: "human_reviewer" },
};

const packet = composeWaggleV0Packets("sequence", [observation, proposal]);
const decoded = decodeWaggleV0(encodeWaggleV0(packet));
const message = createWaggleV0Message({
  missionId: "mission_client_case",
  workNodeId: "work_triage",
  senderAgentId: "agent_analysis",
  receiverActorIds: ["human_reviewer"],
  contextPackId: "context_case_17",
  packet: decoded,
  createdAt: "2026-08-05T00:00:00.000Z",
});

const { service } = createWaggleV0FixtureKea({
  clock: () => "2026-08-05T00:00:01.000Z",
});
const result = service.ingest(message);

console.log(
  JSON.stringify(
    {
      messageId: message.messageId,
      packet: decoded,
      disposition: result.interpretation.disposition,
      exactRoundTrip: result.interpretation.verification.exactRoundTrip,
      authorityGranted: result.interpretation.authorityGranted,
      replay: service.replay(message.messageId),
    },
    null,
    2
  )
);
