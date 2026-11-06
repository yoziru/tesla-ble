add_test([=[ProtocolHandshakeTest.HandshakeRequestGeneration]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_handshake [==[--gtest_filter=ProtocolHandshakeTest.HandshakeRequestGeneration]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolHandshakeTest.HandshakeRequestGeneration]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_handshake.cpp:53]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolHandshakeTest.HandshakeFlowProcessing]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_handshake [==[--gtest_filter=ProtocolHandshakeTest.HandshakeFlowProcessing]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolHandshakeTest.HandshakeFlowProcessing]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_handshake.cpp:87]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolHandshakeTest.ResponseEncryptionFlag]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_handshake [==[--gtest_filter=ProtocolHandshakeTest.ResponseEncryptionFlag]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolHandshakeTest.ResponseEncryptionFlag]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_handshake.cpp:124]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolHandshakeTest.ResponseDecryption]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_handshake [==[--gtest_filter=ProtocolHandshakeTest.ResponseDecryption]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolHandshakeTest.ResponseDecryption]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_handshake.cpp:169]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolHandshakeTest.VcsecResponseDecryptRoundTrip]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_handshake [==[--gtest_filter=ProtocolHandshakeTest.VcsecResponseDecryptRoundTrip]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolHandshakeTest.VcsecResponseDecryptRoundTrip]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_handshake.cpp:223]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolHandshakeTest.DomainSpecificBehavior]=]  /home/dev/dev/tesla-ble/build4/tests/test_protocol_handshake [==[--gtest_filter=ProtocolHandshakeTest.DomainSpecificBehavior]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolHandshakeTest.DomainSpecificBehavior]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_protocol_handshake.cpp:312]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_protocol_handshake_TESTS [==[ProtocolHandshakeTest.HandshakeRequestGeneration]==] [==[ProtocolHandshakeTest.HandshakeFlowProcessing]==] [==[ProtocolHandshakeTest.ResponseEncryptionFlag]==] [==[ProtocolHandshakeTest.ResponseDecryption]==] [==[ProtocolHandshakeTest.VcsecResponseDecryptRoundTrip]==] [==[ProtocolHandshakeTest.DomainSpecificBehavior]==])
