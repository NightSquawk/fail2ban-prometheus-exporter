# Activity evidence and optional billing integration

- Leave a concise completion record in the task handoff or commit/PR description:
  outcome, affected packages/files, branch or commit when applicable, checks run,
  and any deployment or verification limits. Do not invent elapsed time or hashes.
- No billing attribution or external activity inbox is established for this
  exporter. Do not add a client tag, mark work billable, write to an external
  inbox, or install global hooks without a project policy that requires it.
- If the user supplies an activity-logging policy for this project, follow its
  destination and attribution. Reuse existing hooks without duplicate logging,
  exclude secrets, and close completed task entries before moving to other work.
- Machine-specific hook files, credentials, MCP configuration, and absolute paths
  belong to local setup, not the shared project rule set.
