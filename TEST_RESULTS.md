# PS-008 test results

Run: 2026-10-18 15:31 — **27/27 passed**

| # | Scenario | Test | Result |
|---|---|---|---|
| 1 | [Schema] A well-formed OSPF intent is accepted and reaches the approval gate. | `test_valid_ospf_intent_passes` | pass |
| 2 | [Invalid config] A prefix with host bits set (10.0.3.5/24) is rejected by the schema. | `test_malformed_prefix_rejected` | pass |
| 3 | [Security] Extra fields such as raw_commands are rejected — no unrestricted commands. | `test_raw_cli_smuggling_rejected` | pass |
| 4 | [Schema] An intent type outside the two supported kinds is rejected. | `test_unknown_intent_kind_rejected` | pass |
| 5 | [Invalid config] OSPF cost 70000 (> 65535) is rejected. | `test_out_of_range_ospf_cost_rejected` | pass |
| 6 | [Policy] A default route 0.0.0.0/0 is refused by the intent policy. | `test_default_route_blocked_by_policy` | pass |
| 7 | [Invalid config] An intent referencing router R9 (not in the lab) is rejected. | `test_unknown_router_rejected` | pass |
| 8 | [Invalid config] Removing a static route that does not exist is rejected. | `test_removing_missing_route_rejected` | pass |
| 9 | [Invalid config] Re-applying an already-deployed intent is detected as a no-op. | `test_noop_intent_rejected` | pass |
| 10 | [Twin] After OSPF on R1-R2 and R2-R3, all six LAN pairs are reachable in the twin. | `test_twin_computes_full_reachability` | pass |
| 11 | [Conflicting routes] Same prefix with two different next hops on R1 fails validation. | `test_conflicting_static_routes_detected` | pass |
| 12 | [Conflicting routes] R1->R2 and R2->R1 for the same prefix is caught as a routing loop. | `test_routing_loop_detected` | pass |
| 13 | [Conflicting routes] A static route for R1's own LAN (10.0.1.0/24) is flagged as overlapping. | `test_static_overlapping_connected_detected` | pass |
| 14 | [Twin] Disabling the only OSPF path to R3 is blocked as a reachability regression. | `test_reachability_regression_detected` | pass |
| 15 | [Twin] With R1-R3 also in OSPF, disabling R2-R3 is safe (traffic reroutes) and passes. | `test_redundant_path_allows_safe_disable` | pass |
| 16 | [Approval gate] Deploying a change that is still pending approval is refused. | `test_deploy_without_approval_blocked` | pass |
| 17 | [Rejected approval] A rejected change cannot be deployed and the lab is untouched. | `test_rejected_change_never_deployed` | pass |
| 18 | [Approval gate] Four-eyes rule: the requester cannot approve their own change. | `test_self_approval_blocked` | pass |
| 19 | [Approval gate] A change that failed the twin can never be approved. | `test_failed_validation_cannot_be_approved` | pass |
| 20 | [Approval gate] If the network changes after approval, the stale change is refused. | `test_stale_change_blocked_after_drift` | pass |
| 21 | [Deploy] An approved change is applied and the running config equals the candidate. | `test_successful_deploy_matches_candidate` | pass |
| 22 | [Failed deployment] R3 fails mid-commit; R1 and the partial R3 change are both rolled back. | `test_failed_deployment_rolls_back_all_routers` | pass |
| 23 | [Failed deployment] Device acks but silently drops the commit; verification triggers rollback. | `test_silent_failure_caught_by_verification` | pass |
| 24 | [Rollback] A deployed change can be reverted to its saved pre-deploy snapshot. | `test_manual_rollback_restores_snapshot` | pass |
| 25 | [Rollback] Snapshots live on disk: a brand-new agent process can still roll back. | `test_snapshot_is_durable_across_restart` | pass |
| 26 | [Security] The device driver refuses any command outside the allowlist (e.g. 'write erase'). | `test_driver_refuses_non_allowlisted_command` | pass |
| 27 | [Audit] Every action is hash-chained in the audit log; editing an entry is detected. | `test_audit_log_tamper_evident` | pass |
