add_test([=[ProtocolEdgeCasesTest.InvalidPublicKeyFormat]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_edge_cases [==[--gtest_filter=ProtocolEdgeCasesTest.InvalidPublicKeyFormat]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolEdgeCasesTest.InvalidPublicKeyFormat]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_edge_cases.cpp:31]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolEdgeCasesTest.InvalidSessionInfoMissingEpoch]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_edge_cases [==[--gtest_filter=ProtocolEdgeCasesTest.InvalidSessionInfoMissingEpoch]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolEdgeCasesTest.InvalidSessionInfoMissingEpoch]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_edge_cases.cpp:40]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolEdgeCasesTest.CounterOverflow]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_edge_cases [==[--gtest_filter=ProtocolEdgeCasesTest.CounterOverflow]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolEdgeCasesTest.CounterOverflow]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_edge_cases.cpp:51]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolEdgeCasesTest.RequestHashInvalidTagLength]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_edge_cases [==[--gtest_filter=ProtocolEdgeCasesTest.RequestHashInvalidTagLength]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolEdgeCasesTest.RequestHashInvalidTagLength]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_edge_cases.cpp:59]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_protocol_edge_cases_TESTS [==[ProtocolEdgeCasesTest.InvalidPublicKeyFormat]==] [==[ProtocolEdgeCasesTest.InvalidSessionInfoMissingEpoch]==] [==[ProtocolEdgeCasesTest.CounterOverflow]==] [==[ProtocolEdgeCasesTest.RequestHashInvalidTagLength]==])
