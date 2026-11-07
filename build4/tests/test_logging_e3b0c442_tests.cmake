add_test([=[LoggingTest.BasicLogging]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.BasicLogging]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.BasicLogging]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:47]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.LoggingWithFormat]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.LoggingWithFormat]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.LoggingWithFormat]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:56]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.AllLogLevels]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.AllLogLevels]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.AllLogLevels]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:64]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.CustomTagInSource]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.CustomTagInSource]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.CustomTagInSource]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:79]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.NullFormatHandling]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.NullFormatHandling]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.NullFormatHandling]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:86]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.NullTagHandling]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.NullTagHandling]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.NullTagHandling]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:94]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.NoCallbackFallback]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.NoCallbackFallback]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.NoCallbackFallback]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:103]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.FormatHexUtility]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.FormatHexUtility]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.FormatHexUtility]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:114]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.FormatHexEmptyData]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.FormatHexEmptyData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.FormatHexEmptyData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:121]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.FormatHexLargeData]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.FormatHexLargeData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.FormatHexLargeData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:130]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.LongMessage]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.LongMessage]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.LongMessage]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:148]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[LoggingTest.MultipleMessages]=]  /home/dev/dev/tesla-ble/build4/tests/test_logging [==[--gtest_filter=LoggingTest.MultipleMessages]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LoggingTest.MultipleMessages]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_logging.cpp:157]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_logging_TESTS [==[LoggingTest.BasicLogging]==] [==[LoggingTest.LoggingWithFormat]==] [==[LoggingTest.AllLogLevels]==] [==[LoggingTest.CustomTagInSource]==] [==[LoggingTest.NullFormatHandling]==] [==[LoggingTest.NullTagHandling]==] [==[LoggingTest.NoCallbackFallback]==] [==[LoggingTest.FormatHexUtility]==] [==[LoggingTest.FormatHexEmptyData]==] [==[LoggingTest.FormatHexLargeData]==] [==[LoggingTest.LongMessage]==] [==[LoggingTest.MultipleMessages]==])
