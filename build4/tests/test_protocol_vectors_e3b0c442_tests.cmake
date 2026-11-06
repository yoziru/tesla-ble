add_test([=[ProtocolVectorsTest.RequestHashConstruction]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_vectors [==[--gtest_filter=ProtocolVectorsTest.RequestHashConstruction]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolVectorsTest.RequestHashConstruction]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_vectors.cpp:30]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolVectorsTest.CounterAntiReplay]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_vectors [==[--gtest_filter=ProtocolVectorsTest.CounterAntiReplay]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolVectorsTest.CounterAntiReplay]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_vectors.cpp:70]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_protocol_vectors_TESTS [==[ProtocolVectorsTest.RequestHashConstruction]==] [==[ProtocolVectorsTest.CounterAntiReplay]==])
