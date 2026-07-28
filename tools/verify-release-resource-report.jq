def zero_oom:
  .oom == 0 and .oomKill == 0 and .oomGroupKill == 0;

.schemaVersion == 5 and
.passed == true and
.implementation == "rust-release" and
.measurement == "cgroup-v2" and
.binarySha256 == $sha and
.sourceRevision == $revision and
.target == $target and
.workload.concurrentUploads == 4 and
.workload.uploadBytesEach == 67108864 and
.workload.measuredUploadBytes == 268435456 and
.workload.concurrentPulls == 8 and
.workload.pullFrameConcurrencyLimit == 2 and
.workload.replayStormConnections == 11 and
.workload.replayPageSize == 16 and
.workload.replayRevisions == 128 and
.workload.concurrentArgonRequests == 10 and
.workload.bulkMemoryAdmission == {
  totalPermits: 4, argon2Permits: 3, reservedSyncPermits: 1
} and
.workload.concurrentArgon2CompletedChecks >= 1 and
.workload.argon2CompletedChecks >= 2 and
.workload.standaloneArgon2CompletedCheck == true and
.workload.reservedSyncPullBytes == 67108864 and
.workload.reservedSyncPullCompleted == true and
.workload.argon2WithReservedSyncCompleted == true and
.workload.durationMs > 0 and
.workload.websocketConnections == 16 and
.workload.historyRevisions == 128 and
.workload.historyResponseItems == 100 and
.workload.argon2PolicyMaximum == {
  algorithm: "argon2id", version: 19, memoryKiB: 65536,
  timeCost: 5, parallelism: 4, concurrentChecks: 1
} and
.peakRssMeasurement == "linux-vmhwm" and
.baselineRssKiB >= 0 and
.peakRssKiB >= .baselineRssKiB and
.deltaRssKiB == (.peakRssKiB - .baselineRssKiB) and
.peakRssKiB < 229376 and
.deltaRssKiB < 131072 and
.peakRssMiB == (.peakRssKiB / 1024) and
.deltaRssMiB == (.deltaRssKiB / 1024) and
.processRssMarginMiB == (256 - .peakRssMiB) and
.processRssMarginMiB > 32 and
.execution.nativeTarget == $target and
.execution.hostPlatform == "linux" and
(
  ($target == "linux-amd64" and .execution.hostArchitecture == "x64" and
    (.execution.elfDescription | contains("x86-64"))) or
  ($target == "linux-arm64" and .execution.hostArchitecture == "arm64" and
    (.execution.elfDescription | contains("ARM aarch64")))
) and
(.execution.elfDescription | contains("ELF 64-bit")) and
(.execution.elfDescription | test("static-pie linked|statically linked")) and
.execution.nativeRunnerMatch == true and
(.execution.imageId | test("^sha256:[0-9a-f]{64}$")) and
.execution.artifactBinarySha256 == $sha and
.execution.stagedBinarySha256 == $sha and
.execution.inImageBinarySha256 == $sha and
.execution.finalInImageBinarySha256 == $sha and
.execution.identityHashesMatch == true and
.execution.serverOnlyCgroup == true and
.execution.cgroupProcessCount == 1 and
.execution.harnessCgroupSeparated == true and
.execution.containerIsolationPassed == true and
.execution.containerUser == "65532:65532" and
.execution.entrypoint == ["/usr/local/bin/blackglass-server"] and
.execution.command == ["serve"] and
.execution.readOnlyRootFilesystem == true and
.execution.networkMode == "host" and
.execution.pidsLimit == 64 and
(.execution.capDrop | index("ALL")) != null and
(.execution.securityOptions | index("no-new-privileges")) != null and
.cgroup.version == 2 and
(.cgroup.eventsSource == "memory.events.local" or .cgroup.eventsSource == "memory.events") and
.cgroup.memoryPeakBytes > 0 and
.cgroup.memoryMaxBytes == 268435456 and
.cgroup.memorySwapMaxBytes == 0 and
(.cgroup.memoryEventsBefore | zero_oom) and
(.cgroup.memoryEvents | zero_oom) and
(.cgroup.memoryEventDelta | zero_oom) and
.cgroup.memoryEventDelta.low ==
  (.cgroup.memoryEvents.low - .cgroup.memoryEventsBefore.low) and
.cgroup.memoryEventDelta.high ==
  (.cgroup.memoryEvents.high - .cgroup.memoryEventsBefore.high) and
.cgroup.memoryEventDelta.max ==
  (.cgroup.memoryEvents.max - .cgroup.memoryEventsBefore.max) and
.cgroup.memoryEventDelta.oom ==
  (.cgroup.memoryEvents.oom - .cgroup.memoryEventsBefore.oom) and
.cgroup.memoryEventDelta.oomKill ==
  (.cgroup.memoryEvents.oomKill - .cgroup.memoryEventsBefore.oomKill) and
.cgroup.memoryEventDelta.oomGroupKill ==
  (.cgroup.memoryEvents.oomGroupKill - .cgroup.memoryEventsBefore.oomGroupKill) and
.container.dockerMemoryLimitBytes == 268435456 and
.container.dockerMemorySwapTotalBytes == 268435456 and
.container.gracefulExit == true and
.container.exitCode == 0 and
.container.oomKilled == false and
.container.stateError == "" and
.databaseBytes > 268435456 and
.stagingEntries == [".blackglass-staging-v1"] and
.unexpectedStagingEntries == [] and
.limits == {
  serviceMemoryMaxMiB: 256,
  minimumProcessRssMarginMiB: 32,
  maxPeakProcessRssMiB: 224,
  maxDeltaProcessRssMiB: 128,
  memoryMaxBytes: 268435456,
  memorySwapMaxBytes: 0,
  dockerMemorySwapTotalBytes: 268435456
}
