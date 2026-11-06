add_test([=[ClientTest.GetPeerForBothDomains]=]  /home/dev/dev/tesla-ble/build4/tests/test_client [==[--gtest_filter=ClientTest.GetPeerForBothDomains]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ClientTest.GetPeerForBothDomains]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_client.cpp:21]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ClientTest.BuildUniversalMessageUpdatesLastRequestUuid]=]  /home/dev/dev/tesla-ble/build4/tests/test_client [==[--gtest_filter=ClientTest.BuildUniversalMessageUpdatesLastRequestUuid]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ClientTest.BuildUniversalMessageUpdatesLastRequestUuid]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_client.cpp:29]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ClientTest.BuildWhiteListMessageInvalidRole]=]  /home/dev/dev/tesla-ble/build4/tests/test_client [==[--gtest_filter=ClientTest.BuildWhiteListMessageInvalidRole]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ClientTest.BuildWhiteListMessageInvalidRole]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_client.cpp:54]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_client_TESTS [==[ClientTest.GetPeerForBothDomains]==] [==[ClientTest.BuildUniversalMessageUpdatesLastRequestUuid]==] [==[ClientTest.BuildWhiteListMessageInvalidRole]==])
