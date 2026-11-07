add_test([=[SessionManagementTest.GetVCSECPeer]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_management [==[--gtest_filter=SessionManagementTest.GetVCSECPeer]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionManagementTest.GetVCSECPeer]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_management.cpp:29]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionManagementTest.GetInfotainmentPeer]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_management [==[--gtest_filter=SessionManagementTest.GetInfotainmentPeer]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionManagementTest.GetInfotainmentPeer]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_management.cpp:36]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionManagementTest.InitializeVCSECSession]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_management [==[--gtest_filter=SessionManagementTest.InitializeVCSECSession]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionManagementTest.InitializeVCSECSession]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_management.cpp:43]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionManagementTest.InitializeInfotainmentSession]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_management [==[--gtest_filter=SessionManagementTest.InitializeInfotainmentSession]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionManagementTest.InitializeInfotainmentSession]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_management.cpp:65]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionManagementTest.UpdateSessionWithNullSessionInfo]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_management [==[--gtest_filter=SessionManagementTest.UpdateSessionWithNullSessionInfo]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionManagementTest.UpdateSessionWithNullSessionInfo]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_management.cpp:88]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[SessionManagementTest.MultipleSessionUpdates]=]  /home/dev/dev/tesla-ble/build4/tests/test_session_management [==[--gtest_filter=SessionManagementTest.MultipleSessionUpdates]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[SessionManagementTest.MultipleSessionUpdates]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_session_management.cpp:97]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_session_management_TESTS [==[SessionManagementTest.GetVCSECPeer]==] [==[SessionManagementTest.GetInfotainmentPeer]==] [==[SessionManagementTest.InitializeVCSECSession]==] [==[SessionManagementTest.InitializeInfotainmentSession]==] [==[SessionManagementTest.UpdateSessionWithNullSessionInfo]==] [==[SessionManagementTest.MultipleSessionUpdates]==])
