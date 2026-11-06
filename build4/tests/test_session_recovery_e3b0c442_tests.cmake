add_test([=[SessionRecoveryTest.UpdateSessionWithHigherCounter]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.UpdateSessionWithHigherCounter]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.UpdateSessionWithHigherCounter]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:61]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.UpdateSessionRejectsLowerCounter]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.UpdateSessionRejectsLowerCounter]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.UpdateSessionRejectsLowerCounter]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:78]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.ForceUpdateSessionAcceptsLowerCounter]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.ForceUpdateSessionAcceptsLowerCounter]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.ForceUpdateSessionAcceptsLowerCounter]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:95]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.ForceUpdateSessionRestoresValidity]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.ForceUpdateSessionRestoresValidity]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.ForceUpdateSessionRestoresValidity]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:121]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.ForceUpdateSessionWithEpochChange]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.ForceUpdateSessionWithEpochChange]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.ForceUpdateSessionWithEpochChange]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:142]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.ForceUpdateSessionWithNullInfo]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.ForceUpdateSessionWithNullInfo]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.ForceUpdateSessionWithNullInfo]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:172]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.FullSessionRecoveryFlow]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.FullSessionRecoveryFlow]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.FullSessionRecoveryFlow]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:185]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.IsInitializedReturnsFalseWhenInvalid]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.IsInitializedReturnsFalseWhenInvalid]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.IsInitializedReturnsFalseWhenInvalid]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:213]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.UpdateSessionWithSameCounter]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.UpdateSessionWithSameCounter]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.UpdateSessionWithSameCounter]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:228]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.NewAuthenticatedEpochAcceptsCounterOne]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.NewAuthenticatedEpochAcceptsCounterOne]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.NewAuthenticatedEpochAcceptsCounterOne]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:238]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.ResetSessionAcceptsCounterOne]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.ResetSessionAcceptsCounterOne]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.ResetSessionAcceptsCounterOne]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:251]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.FailedForceUpdatePreservesResponseWindow]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.FailedForceUpdatePreservesResponseWindow]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.FailedForceUpdatePreservesResponseWindow]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:261]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionRecoveryTest.SessionInfoWithoutPublicKeyDoesNotMarkSessionValid]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_recovery [==[--gtest_filter=SessionRecoveryTest.SessionInfoWithoutPublicKeyDoesNotMarkSessionValid]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionRecoveryTest.SessionInfoWithoutPublicKeyDoesNotMarkSessionValid]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_recovery.cpp:274]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_session_recovery_TESTS [==[SessionRecoveryTest.UpdateSessionWithHigherCounter]==] [==[SessionRecoveryTest.UpdateSessionRejectsLowerCounter]==] [==[SessionRecoveryTest.ForceUpdateSessionAcceptsLowerCounter]==] [==[SessionRecoveryTest.ForceUpdateSessionRestoresValidity]==] [==[SessionRecoveryTest.ForceUpdateSessionWithEpochChange]==] [==[SessionRecoveryTest.ForceUpdateSessionWithNullInfo]==] [==[SessionRecoveryTest.FullSessionRecoveryFlow]==] [==[SessionRecoveryTest.IsInitializedReturnsFalseWhenInvalid]==] [==[SessionRecoveryTest.UpdateSessionWithSameCounter]==] [==[SessionRecoveryTest.NewAuthenticatedEpochAcceptsCounterOne]==] [==[SessionRecoveryTest.ResetSessionAcceptsCounterOne]==] [==[SessionRecoveryTest.FailedForceUpdatePreservesResponseWindow]==] [==[SessionRecoveryTest.SessionInfoWithoutPublicKeyDoesNotMarkSessionValid]==])
