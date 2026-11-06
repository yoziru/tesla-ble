add_test([=[ProtocolFailureTest.PrivateKeyPemParsing]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_compliance [==[--gtest_filter=ProtocolFailureTest.PrivateKeyPemParsing]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolFailureTest.PrivateKeyPemParsing]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_compliance.cpp:20]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolFailureTest.EcdhKeyAgreement]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_compliance [==[--gtest_filter=ProtocolFailureTest.EcdhKeyAgreement]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolFailureTest.EcdhKeyAgreement]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_compliance.cpp:34]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolFailureTest.SessionInfoAuthentication]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_compliance [==[--gtest_filter=ProtocolFailureTest.SessionInfoAuthentication]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolFailureTest.SessionInfoAuthentication]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_compliance.cpp:67]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolFailureTest.ClientStrictValidation]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_compliance [==[--gtest_filter=ProtocolFailureTest.ClientStrictValidation]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolFailureTest.ClientStrictValidation]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_compliance.cpp:100]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolFailureTest.CounterAntiReplay]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_compliance [==[--gtest_filter=ProtocolFailureTest.CounterAntiReplay]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolFailureTest.CounterAntiReplay]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_compliance.cpp:127]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_protocol_compliance_TESTS [==[ProtocolFailureTest.PrivateKeyPemParsing]==] [==[ProtocolFailureTest.EcdhKeyAgreement]==] [==[ProtocolFailureTest.SessionInfoAuthentication]==] [==[ProtocolFailureTest.ClientStrictValidation]==] [==[ProtocolFailureTest.CounterAntiReplay]==])
