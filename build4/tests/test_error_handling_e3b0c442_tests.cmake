add_test([=[ErrorHandlingTest.ErrorCodeToStringMapping]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.ErrorCodeToStringMapping]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.ErrorCodeToStringMapping]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:44]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.UnknownErrorCode]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.UnknownErrorCode]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.UnknownErrorCode]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:54]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.AllErrorCodesAreMapped]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.AllErrorCodesAreMapped]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.AllErrorCodesAreMapped]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:70]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.BuildMessageWithoutPrivateKey]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.BuildMessageWithoutPrivateKey]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.BuildMessageWithoutPrivateKey]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:83]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.BuildMessageWithNullParameters]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.BuildMessageWithNullParameters]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.BuildMessageWithNullParameters]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:104]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.ParseMessageWithNullParameters]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.ParseMessageWithNullParameters]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.ParseMessageWithNullParameters]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:125]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.ParseSessionInfoWithNullParameters]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.ParseSessionInfoWithNullParameters]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.ParseSessionInfoWithNullParameters]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:142]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.PrivateKeyOperationsWithoutKey]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.PrivateKeyOperationsWithoutKey]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.PrivateKeyOperationsWithoutKey]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:159]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.EdgeCaseFunctionCalls]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.EdgeCaseFunctionCalls]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.EdgeCaseFunctionCalls]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:168]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ErrorHandlingTest.BuildUniversalMessageRejectsOversizedPayload]=]  /home/dev/dev/tesla-ble/build4/tests/test_error_handling [==[--gtest_filter=ErrorHandlingTest.BuildUniversalMessageRejectsOversizedPayload]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ErrorHandlingTest.BuildUniversalMessageRejectsOversizedPayload]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_error_handling.cpp:200]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_error_handling_TESTS [==[ErrorHandlingTest.ErrorCodeToStringMapping]==] [==[ErrorHandlingTest.UnknownErrorCode]==] [==[ErrorHandlingTest.AllErrorCodesAreMapped]==] [==[ErrorHandlingTest.BuildMessageWithoutPrivateKey]==] [==[ErrorHandlingTest.BuildMessageWithNullParameters]==] [==[ErrorHandlingTest.ParseMessageWithNullParameters]==] [==[ErrorHandlingTest.ParseSessionInfoWithNullParameters]==] [==[ErrorHandlingTest.PrivateKeyOperationsWithoutKey]==] [==[ErrorHandlingTest.EdgeCaseFunctionCalls]==] [==[ErrorHandlingTest.BuildUniversalMessageRejectsOversizedPayload]==])
