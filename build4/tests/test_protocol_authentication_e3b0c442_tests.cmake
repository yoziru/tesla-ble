add_test([=[ProtocolAuthenticationTest.AuthenticationStateTransitions]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_authentication [==[--gtest_filter=ProtocolAuthenticationTest.AuthenticationStateTransitions]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolAuthenticationTest.AuthenticationStateTransitions]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_authentication.cpp:32]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolAuthenticationTest.MetadataSerializationEdgeCases]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_authentication [==[--gtest_filter=ProtocolAuthenticationTest.MetadataSerializationEdgeCases]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolAuthenticationTest.MetadataSerializationEdgeCases]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_authentication.cpp:62]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolAuthenticationTest.CounterEdgeCases]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_authentication [==[--gtest_filter=ProtocolAuthenticationTest.CounterEdgeCases]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolAuthenticationTest.CounterEdgeCases]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_authentication.cpp:100]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolAuthenticationTest.TimeAndExpirationHandling]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_authentication [==[--gtest_filter=ProtocolAuthenticationTest.TimeAndExpirationHandling]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolAuthenticationTest.TimeAndExpirationHandling]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_authentication.cpp:122]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolAuthenticationTest.NonceGeneration]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_authentication [==[--gtest_filter=ProtocolAuthenticationTest.NonceGeneration]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolAuthenticationTest.NonceGeneration]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_authentication.cpp:154]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolAuthenticationTest.SessionStateValidation]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_authentication [==[--gtest_filter=ProtocolAuthenticationTest.SessionStateValidation]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolAuthenticationTest.SessionStateValidation]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_authentication.cpp:188]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolAuthenticationTest.ErrorConditions]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_authentication [==[--gtest_filter=ProtocolAuthenticationTest.ErrorConditions]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolAuthenticationTest.ErrorConditions]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_authentication.cpp:225]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolAuthenticationTest.ProtocolCompatibility]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_authentication [==[--gtest_filter=ProtocolAuthenticationTest.ProtocolCompatibility]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolAuthenticationTest.ProtocolCompatibility]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_authentication.cpp:262]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_protocol_authentication_TESTS [==[ProtocolAuthenticationTest.AuthenticationStateTransitions]==] [==[ProtocolAuthenticationTest.MetadataSerializationEdgeCases]==] [==[ProtocolAuthenticationTest.CounterEdgeCases]==] [==[ProtocolAuthenticationTest.TimeAndExpirationHandling]==] [==[ProtocolAuthenticationTest.NonceGeneration]==] [==[ProtocolAuthenticationTest.SessionStateValidation]==] [==[ProtocolAuthenticationTest.ErrorConditions]==] [==[ProtocolAuthenticationTest.ProtocolCompatibility]==])
