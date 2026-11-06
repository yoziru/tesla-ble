add_test([=[VehicleTest.ConnectionStateTransitions]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ConnectionStateTransitions]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ConnectionStateTransitions]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:448]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakeCommandSendsData]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakeCommandSendsData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakeCommandSendsData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:462]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.VCSECPollSendsData]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.VCSECPollSendsData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.VCSECPollSendsData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:473]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.InfotainmentPollWithForceWakeSendsData]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.InfotainmentPollWithForceWakeSendsData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.InfotainmentPollWithForceWakeSendsData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:482]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.InfotainmentPollCompletesOnResponse]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.InfotainmentPollCompletesOnResponse]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.InfotainmentPollCompletesOnResponse]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:491]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.PollAndChargingCommandResponsesStaySerialized]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.PollAndChargingCommandResponsesStaySerialized]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.PollAndChargingCommandResponsesStaySerialized]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:546]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.CounterReplaySessionInfoIsAppliedInsteadOfRejected]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.CounterReplaySessionInfoIsAppliedInsteadOfRejected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.CounterReplaySessionInfoIsAppliedInsteadOfRejected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:594]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.StoredSessionWithFutureClockTimeIsNotRejected]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.StoredSessionWithFutureClockTimeIsNotRejected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.StoredSessionWithFutureClockTimeIsNotRejected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:634]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.InfotainmentActionFailureSurfacesPlainTextReason]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.InfotainmentActionFailureSurfacesPlainTextReason]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.InfotainmentActionFailureSurfacesPlainTextReason]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:677]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.AlreadySetActionIsAnIdempotentSuccess]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.AlreadySetActionIsAnIdempotentSuccess]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.AlreadySetActionIsAnIdempotentSuccess]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:736]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SetChargingAmpsSendsData]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SetChargingAmpsSendsData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SetChargingAmpsSendsData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:781]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SetChargingLimitSendsData]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SetChargingLimitSendsData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SetChargingLimitSendsData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:790]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ScheduleSoftwareUpdateRejectsNegativeOffset]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ScheduleSoftwareUpdateRejectsNegativeOffset]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ScheduleSoftwareUpdateRejectsNegativeOffset]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:799]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.CommandCallbackIsInvokedOnSuccess]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.CommandCallbackIsInvokedOnSuccess]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.CommandCallbackIsInvokedOnSuccess]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:819]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.CommandCallbackReceivesFailureOnDisconnect]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.CommandCallbackReceivesFailureOnDisconnect]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.CommandCallbackReceivesFailureOnDisconnect]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:856]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.NullCallbackIsHandledSafely]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.NullCallbackIsHandledSafely]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.NullCallbackIsHandledSafely]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:878]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ReceivingDataDoesNotCrash]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ReceivingDataDoesNotCrash]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ReceivingDataDoesNotCrash]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:896]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ReceivingPartialDataDoesNotCrash]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ReceivingPartialDataDoesNotCrash]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ReceivingPartialDataDoesNotCrash]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:902]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ReceivingEmptyDataDoesNotCrash]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ReceivingEmptyDataDoesNotCrash]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ReceivingEmptyDataDoesNotCrash]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:908]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ReceivingValidSessionInfoCompletesAuth]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ReceivingValidSessionInfoCompletesAuth]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ReceivingValidSessionInfoCompletesAuth]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:913]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.RecoverySkipsCorruptPrefix]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.RecoverySkipsCorruptPrefix]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.RecoverySkipsCorruptPrefix]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:951]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SplitFrameAcrossNotificationsIsReassembled]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SplitFrameAcrossNotificationsIsReassembled]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SplitFrameAcrossNotificationsIsReassembled]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:970]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.MultipleFramesInOneNotificationAreProcessed]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.MultipleFramesInOneNotificationAreProcessed]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.MultipleFramesInOneNotificationAreProcessed]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:982]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.CorruptLengthBeforeSplitFrameDoesNotDiscardValidFrame]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.CorruptLengthBeforeSplitFrameDoesNotDiscardValidFrame]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.CorruptLengthBeforeSplitFrameDoesNotDiscardValidFrame]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:995]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.MalformedProtobufBeforeValidFrameIsSkipped]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.MalformedProtobufBeforeValidFrameIsSkipped]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.MalformedProtobufBeforeValidFrameIsSkipped]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1009]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.IdenticalNotificationsAcrossReconnectArePreserved]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.IdenticalNotificationsAcrossReconnectArePreserved]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.IdenticalNotificationsAcrossReconnectArePreserved]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1022]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.DisconnectDiscardsDecodedRepliesBeforeReconnect]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.DisconnectDiscardsDecodedRepliesBeforeReconnect]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.DisconnectDiscardsDecodedRepliesBeforeReconnect]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1037]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.UnknownSleepObservationDoesNotMeanAwake]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.UnknownSleepObservationDoesNotMeanAwake]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.UnknownSleepObservationDoesNotMeanAwake]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1053]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.DisconnectDuringObservationDefersNewConnectionMessages]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.DisconnectDuringObservationDefersNewConnectionMessages]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.DisconnectDuringObservationDefersNewConnectionMessages]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1064]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.DisconnectDuringMessageCallbackDiscardsCurrentObservation]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.DisconnectDuringMessageCallbackDiscardsCurrentObservation]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.DisconnectDuringMessageCallbackDiscardsCurrentObservation]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1083]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.DisconnectClearsAuthenticationState]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.DisconnectClearsAuthenticationState]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.DisconnectClearsAuthenticationState]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1113]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.DisconnectClearsAllPendingCommands]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.DisconnectClearsAllPendingCommands]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.DisconnectClearsAllPendingCommands]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1129]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SignedSessionInfoKeyNotOnWhitelistReportsPairingError]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SignedSessionInfoKeyNotOnWhitelistReportsPairingError]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SignedSessionInfoKeyNotOnWhitelistReportsPairingError]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1167]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SessionInfoKeyNotOnWhitelistDoesNotUpdatePeerSession]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SessionInfoKeyNotOnWhitelistDoesNotUpdatePeerSession]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SessionInfoKeyNotOnWhitelistDoesNotUpdatePeerSession]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1217]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.DisconnectClearsPartiallyReceivedData]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.DisconnectClearsPartiallyReceivedData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.DisconnectClearsPartiallyReceivedData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1265]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.DisconnectWithEmptyQueueDoesNotCrash]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.DisconnectWithEmptyQueueDoesNotCrash]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.DisconnectWithEmptyQueueDoesNotCrash]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1279]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ReconnectionAllowsFreshCommands]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ReconnectionAllowsFreshCommands]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ReconnectionAllowsFreshCommands]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1281]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.MultipleDisconnectsOnlyCallbackOnce]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.MultipleDisconnectsOnlyCallbackOnce]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.MultipleDisconnectsOnlyCallbackOnce]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1298]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.PairingWhitelistRequestUsesCommandTimeout]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.PairingWhitelistRequestUsesCommandTimeout]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.PairingWhitelistRequestUsesCommandTimeout]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1354]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.InfotainmentWakeTransitionResetsCommandTimeoutBudget]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.InfotainmentWakeTransitionResetsCommandTimeoutBudget]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.InfotainmentWakeTransitionResetsCommandTimeoutBudget]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1379]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakeStatusBurstSendsOneInfotainmentSessionRequest]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakeStatusBurstSendsOneInfotainmentSessionRequest]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakeStatusBurstSendsOneInfotainmentSessionRequest]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1442]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakeWaitPollsStatusWithoutBlockingOnQueuedCommands]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakeWaitPollsStatusWithoutBlockingOnQueuedCommands]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakeWaitPollsStatusWithoutBlockingOnQueuedCommands]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1485]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakeSessionRecoveryRebuildsRequestsAndRemainsBounded]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakeSessionRecoveryRebuildsRequestsAndRemainsBounded]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakeSessionRecoveryRebuildsRequestsAndRemainsBounded]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1557]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.UnansweredSessionRequestIsResentUnchangedEverySecond]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.UnansweredSessionRequestIsResentUnchangedEverySecond]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.UnansweredSessionRequestIsResentUnchangedEverySecond]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1615]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ResponseTimeoutResendsTheSameMessage]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ResponseTimeoutResendsTheSameMessage]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ResponseTimeoutResendsTheSameMessage]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1663]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ErrorTimeExpiredTriggersSessionResetAndReAuth]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ErrorTimeExpiredTriggersSessionResetAndReAuth]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ErrorTimeExpiredTriggersSessionResetAndReAuth]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1763]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SignedMessageRejectionCompletesDuringRetryBackoff]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SignedMessageRejectionCompletesDuringRetryBackoff]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SignedMessageRejectionCompletesDuringRetryBackoff]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1860]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SignedMessageCorrelationProtectsPendingControl]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SignedMessageCorrelationProtectsPendingControl]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SignedMessageCorrelationProtectsPendingControl]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1902]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.UnknownKeyDuringPollReportsPairingRequired]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.UnknownKeyDuringPollReportsPairingRequired]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.UnknownKeyDuringPollReportsPairingRequired]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1962]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.StaleVcsecResponsesObserveButDoNotCompleteNewControl]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.StaleVcsecResponsesObserveButDoNotCompleteNewControl]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.StaleVcsecResponsesObserveButDoNotCompleteNewControl]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1985]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SessionCorrelationUsesAuthAndWakePrerequisiteDomains]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SessionCorrelationUsesAuthAndWakePrerequisiteDomains]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SessionCorrelationUsesAuthAndWakePrerequisiteDomains]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2038]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.UnsignedKeyRejectionSignalsRepairWithoutEstablishingSession]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.UnsignedKeyRejectionSignalsRepairWithoutEstablishingSession]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.UnsignedKeyRejectionSignalsRepairWithoutEstablishingSession]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2111]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.MissingSessionInfoHmacTagFailsAuthGracefully]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.MissingSessionInfoHmacTagFailsAuthGracefully]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.MissingSessionInfoHmacTagFailsAuthGracefully]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2142]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SessionInfoOutsideLatencyWindowCannotRestoreSession]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SessionInfoOutsideLatencyWindowCannotRestoreSession]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SessionInfoOutsideLatencyWindowCannotRestoreSession]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2185]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.MissingSessionInfoHmacTagDoesNotBlockSubsequentCommands]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.MissingSessionInfoHmacTagDoesNotBlockSubsequentCommands]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.MissingSessionInfoHmacTagDoesNotBlockSubsequentCommands]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2220]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.PairingBypassesAuthEvenWhenVcsecAuthIsFailing]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.PairingBypassesAuthEvenWhenVcsecAuthIsFailing]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.PairingBypassesAuthEvenWhenVcsecAuthIsFailing]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2272]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.NoWakeSkipSkipsWhenVehicleAsleep]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.NoWakeSkipSkipsWhenVehicleAsleep]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.NoWakeSkipSkipsWhenVehicleAsleep]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2311]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.NoWakeFailWhenVehicleAsleep]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.NoWakeFailWhenVehicleAsleep]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.NoWakeFailWhenVehicleAsleep]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2338]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakeIfNeededProceedsWhenAwake]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakeIfNeededProceedsWhenAwake]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakeIfNeededProceedsWhenAwake]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2365]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakeIfNeededTriggersWakeWhenAsleep]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakeIfNeededTriggersWakeWhenAsleep]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakeIfNeededTriggersWakeWhenAsleep]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2383]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakePolicyRichOutcomeCallbackDistinguishesSkipped]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakePolicyRichOutcomeCallbackDistinguishesSkipped]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakePolicyRichOutcomeCallbackDistinguishesSkipped]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2401]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakePolicyRichOutcomeCallbackDistinguishesFailed]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakePolicyRichOutcomeCallbackDistinguishesFailed]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakePolicyRichOutcomeCallbackDistinguishesFailed]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2429]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakePhaseTimeoutDoesNotConsumeFinalResponseBudget]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakePhaseTimeoutDoesNotConsumeFinalResponseBudget]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakePhaseTimeoutDoesNotConsumeFinalResponseBudget]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2458]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.AuthPhaseTimeoutIndependentFromFinalResponseTimeout]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.AuthPhaseTimeoutIndependentFromFinalResponseTimeout]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.AuthPhaseTimeoutIndependentFromFinalResponseTimeout]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2505]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WrapperCanObserveSkippedOutcomeWithoutInspectingInternals]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WrapperCanObserveSkippedOutcomeWithoutInspectingInternals]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WrapperCanObserveSkippedOutcomeWithoutInspectingInternals]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2544]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WrapperCanObservePhaseTransitions]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WrapperCanObservePhaseTransitions]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WrapperCanObservePhaseTransitions]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2572]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.AuthStallReportsFailureOnceAndDisconnects]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.AuthStallReportsFailureOnceAndDisconnects]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.AuthStallReportsFailureOnceAndDisconnects]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2707]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.AuthTimeoutRaisesRetryLevelBeforeFailing]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.AuthTimeoutRaisesRetryLevelBeforeFailing]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.AuthTimeoutRaisesRetryLevelBeforeFailing]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2747]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.RegenerateKeyResetsSessionsAndStoredCredentials]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.RegenerateKeyResetsSessionsAndStoredCredentials]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.RegenerateKeyResetsSessionsAndStoredCredentials]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2780]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.LockActionCallbackReceivesFailureWhenDisconnected]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.LockActionCallbackReceivesFailureWhenDisconnected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.LockActionCallbackReceivesFailureWhenDisconnected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2826]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.WakeActionCallbackReceivesSkippedWhenAwake]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.WakeActionCallbackReceivesSkippedWhenAwake]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.WakeActionCallbackReceivesSkippedWhenAwake]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2840]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SetChargingAmpsCallbackReceivesBuildFailureForInvalidValue]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SetChargingAmpsCallbackReceivesBuildFailureForInvalidValue]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SetChargingAmpsCallbackReceivesBuildFailureForInvalidValue]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2853]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SetClimateActionCallbackReceivesSuccessOnAlreadySet]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SetClimateActionCallbackReceivesSuccessOnAlreadySet]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SetClimateActionCallbackReceivesSuccessOnAlreadySet]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2865]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.RegenerateKeyCallbackReceivesSuccess]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.RegenerateKeyCallbackReceivesSuccess]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.RegenerateKeyCallbackReceivesSuccess]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2896]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.PendingCommandCountTracksQueue]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.PendingCommandCountTracksQueue]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.PendingCommandCountTracksQueue]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2913]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.HasPrivateKeyReflectsStorage]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.HasPrivateKeyReflectsStorage]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.HasPrivateKeyReflectsStorage]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2922]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.SuccessfulActionSchedulesFollowUpPoll]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.SuccessfulActionSchedulesFollowUpPoll]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.SuccessfulActionSchedulesFollowUpPoll]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2931]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.ClimateActionSchedulesChargeIndependentFollowUp]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.ClimateActionSchedulesChargeIndependentFollowUp]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.ClimateActionSchedulesChargeIndependentFollowUp]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2962]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.PairingWaitsForWhitelistConfirmation]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.PairingWaitsForWhitelistConfirmation]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.PairingWaitsForWhitelistConfirmation]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2998]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.PairingRejectsOuterAndNestedErrors]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.PairingRejectsOuterAndNestedErrors]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.PairingRejectsOuterAndNestedErrors]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:3023]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.CompletionCanDisconnectWithoutReportingAgain]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.CompletionCanDisconnectWithoutReportingAgain]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.CompletionCanDisconnectWithoutReportingAgain]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:3054]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.DisconnectCallbacksCanDisconnectAndReconnect]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.DisconnectCallbacksCanDisconnectAndReconnect]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.DisconnectCallbacksCanDisconnectAndReconnect]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:3083]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.PhaseCallbacksCanCancelWithoutSendingOrCompletingTwice]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.PhaseCallbacksCanCancelWithoutSendingOrCompletingTwice]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.PhaseCallbacksCanCancelWithoutSendingOrCompletingTwice]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:3107]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.FollowUpPollsCoalesceAndClearOnDisconnect]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.FollowUpPollsCoalesceAndClearOnDisconnect]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.FollowUpPollsCoalesceAndClearOnDisconnect]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:3141]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.FullQueueRetainsDeferredFollowUpUntilSpaceIsAvailable]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.FullQueueRetainsDeferredFollowUpUntilSpaceIsAvailable]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.FullQueueRetainsDeferredFollowUpUntilSpaceIsAvailable]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:3165]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleTest.VcsecPollCallbackReportsCompletion]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleTest.VcsecPollCallbackReportsCompletion]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleTest.VcsecPollCallbackReportsCompletion]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:3194]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehiclePairingTest.PairPersistsGeneratedKeyAndSendsDirectWhitelistRequest]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehiclePairingTest.PairPersistsGeneratedKeyAndSendsDirectWhitelistRequest]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehiclePairingTest.PairPersistsGeneratedKeyAndSendsDirectWhitelistRequest]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:1318]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleInternalTest.ExpectedLengthIncludesHeader]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleInternalTest.ExpectedLengthIncludesHeader]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleInternalTest.ExpectedLengthIncludesHeader]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2636]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[VehicleInternalTest.CommandCompletesAfterTimeoutWithPartialData]=]  /home/dev/dev/tesla-ble/build4/tests/test_vehicle [==[--gtest_filter=VehicleInternalTest.CommandCompletesAfterTimeoutWithPartialData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[VehicleInternalTest.CommandCompletesAfterTimeoutWithPartialData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_vehicle.cpp:2643]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_vehicle_TESTS [==[VehicleTest.ConnectionStateTransitions]==] [==[VehicleTest.WakeCommandSendsData]==] [==[VehicleTest.VCSECPollSendsData]==] [==[VehicleTest.InfotainmentPollWithForceWakeSendsData]==] [==[VehicleTest.InfotainmentPollCompletesOnResponse]==] [==[VehicleTest.PollAndChargingCommandResponsesStaySerialized]==] [==[VehicleTest.CounterReplaySessionInfoIsAppliedInsteadOfRejected]==] [==[VehicleTest.StoredSessionWithFutureClockTimeIsNotRejected]==] [==[VehicleTest.InfotainmentActionFailureSurfacesPlainTextReason]==] [==[VehicleTest.AlreadySetActionIsAnIdempotentSuccess]==] [==[VehicleTest.SetChargingAmpsSendsData]==] [==[VehicleTest.SetChargingLimitSendsData]==] [==[VehicleTest.ScheduleSoftwareUpdateRejectsNegativeOffset]==] [==[VehicleTest.CommandCallbackIsInvokedOnSuccess]==] [==[VehicleTest.CommandCallbackReceivesFailureOnDisconnect]==] [==[VehicleTest.NullCallbackIsHandledSafely]==] [==[VehicleTest.ReceivingDataDoesNotCrash]==] [==[VehicleTest.ReceivingPartialDataDoesNotCrash]==] [==[VehicleTest.ReceivingEmptyDataDoesNotCrash]==] [==[VehicleTest.ReceivingValidSessionInfoCompletesAuth]==] [==[VehicleTest.RecoverySkipsCorruptPrefix]==] [==[VehicleTest.SplitFrameAcrossNotificationsIsReassembled]==] [==[VehicleTest.MultipleFramesInOneNotificationAreProcessed]==] [==[VehicleTest.CorruptLengthBeforeSplitFrameDoesNotDiscardValidFrame]==] [==[VehicleTest.MalformedProtobufBeforeValidFrameIsSkipped]==] [==[VehicleTest.IdenticalNotificationsAcrossReconnectArePreserved]==] [==[VehicleTest.DisconnectDiscardsDecodedRepliesBeforeReconnect]==] [==[VehicleTest.UnknownSleepObservationDoesNotMeanAwake]==] [==[VehicleTest.DisconnectDuringObservationDefersNewConnectionMessages]==] [==[VehicleTest.DisconnectDuringMessageCallbackDiscardsCurrentObservation]==] [==[VehicleTest.DisconnectClearsAuthenticationState]==] [==[VehicleTest.DisconnectClearsAllPendingCommands]==] [==[VehicleTest.SignedSessionInfoKeyNotOnWhitelistReportsPairingError]==] [==[VehicleTest.SessionInfoKeyNotOnWhitelistDoesNotUpdatePeerSession]==] [==[VehicleTest.DisconnectClearsPartiallyReceivedData]==] [==[VehicleTest.DisconnectWithEmptyQueueDoesNotCrash]==] [==[VehicleTest.ReconnectionAllowsFreshCommands]==] [==[VehicleTest.MultipleDisconnectsOnlyCallbackOnce]==] [==[VehicleTest.PairingWhitelistRequestUsesCommandTimeout]==] [==[VehicleTest.InfotainmentWakeTransitionResetsCommandTimeoutBudget]==] [==[VehicleTest.WakeStatusBurstSendsOneInfotainmentSessionRequest]==] [==[VehicleTest.WakeWaitPollsStatusWithoutBlockingOnQueuedCommands]==] [==[VehicleTest.WakeSessionRecoveryRebuildsRequestsAndRemainsBounded]==] [==[VehicleTest.UnansweredSessionRequestIsResentUnchangedEverySecond]==] [==[VehicleTest.ResponseTimeoutResendsTheSameMessage]==] [==[VehicleTest.ErrorTimeExpiredTriggersSessionResetAndReAuth]==] [==[VehicleTest.SignedMessageRejectionCompletesDuringRetryBackoff]==] [==[VehicleTest.SignedMessageCorrelationProtectsPendingControl]==] [==[VehicleTest.UnknownKeyDuringPollReportsPairingRequired]==] [==[VehicleTest.StaleVcsecResponsesObserveButDoNotCompleteNewControl]==] [==[VehicleTest.SessionCorrelationUsesAuthAndWakePrerequisiteDomains]==] [==[VehicleTest.UnsignedKeyRejectionSignalsRepairWithoutEstablishingSession]==] [==[VehicleTest.MissingSessionInfoHmacTagFailsAuthGracefully]==] [==[VehicleTest.SessionInfoOutsideLatencyWindowCannotRestoreSession]==] [==[VehicleTest.MissingSessionInfoHmacTagDoesNotBlockSubsequentCommands]==] [==[VehicleTest.PairingBypassesAuthEvenWhenVcsecAuthIsFailing]==] [==[VehicleTest.NoWakeSkipSkipsWhenVehicleAsleep]==] [==[VehicleTest.NoWakeFailWhenVehicleAsleep]==] [==[VehicleTest.WakeIfNeededProceedsWhenAwake]==] [==[VehicleTest.WakeIfNeededTriggersWakeWhenAsleep]==] [==[VehicleTest.WakePolicyRichOutcomeCallbackDistinguishesSkipped]==] [==[VehicleTest.WakePolicyRichOutcomeCallbackDistinguishesFailed]==] [==[VehicleTest.WakePhaseTimeoutDoesNotConsumeFinalResponseBudget]==] [==[VehicleTest.AuthPhaseTimeoutIndependentFromFinalResponseTimeout]==] [==[VehicleTest.WrapperCanObserveSkippedOutcomeWithoutInspectingInternals]==] [==[VehicleTest.WrapperCanObservePhaseTransitions]==] [==[VehicleTest.AuthStallReportsFailureOnceAndDisconnects]==] [==[VehicleTest.AuthTimeoutRaisesRetryLevelBeforeFailing]==] [==[VehicleTest.RegenerateKeyResetsSessionsAndStoredCredentials]==] [==[VehicleTest.LockActionCallbackReceivesFailureWhenDisconnected]==] [==[VehicleTest.WakeActionCallbackReceivesSkippedWhenAwake]==] [==[VehicleTest.SetChargingAmpsCallbackReceivesBuildFailureForInvalidValue]==] [==[VehicleTest.SetClimateActionCallbackReceivesSuccessOnAlreadySet]==] [==[VehicleTest.RegenerateKeyCallbackReceivesSuccess]==] [==[VehicleTest.PendingCommandCountTracksQueue]==] [==[VehicleTest.HasPrivateKeyReflectsStorage]==] [==[VehicleTest.SuccessfulActionSchedulesFollowUpPoll]==] [==[VehicleTest.ClimateActionSchedulesChargeIndependentFollowUp]==] [==[VehicleTest.PairingWaitsForWhitelistConfirmation]==] [==[VehicleTest.PairingRejectsOuterAndNestedErrors]==] [==[VehicleTest.CompletionCanDisconnectWithoutReportingAgain]==] [==[VehicleTest.DisconnectCallbacksCanDisconnectAndReconnect]==] [==[VehicleTest.PhaseCallbacksCanCancelWithoutSendingOrCompletingTwice]==] [==[VehicleTest.FollowUpPollsCoalesceAndClearOnDisconnect]==] [==[VehicleTest.FullQueueRetainsDeferredFollowUpUntilSpaceIsAvailable]==] [==[VehicleTest.VcsecPollCallbackReportsCompletion]==] [==[VehiclePairingTest.PairPersistsGeneratedKeyAndSendsDirectWhitelistRequest]==] [==[VehicleInternalTest.ExpectedLengthIncludesHeader]==] [==[VehicleInternalTest.CommandCompletesAfterTimeoutWithPartialData]==])
