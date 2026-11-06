add_test([=[TBUtilsTest.PbEncodeFieldsValidMessage]=]  /home/dev/dev/tesla-ble/build4/tests/test_tb_utils [==[--gtest_filter=TBUtilsTest.PbEncodeFieldsValidMessage]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[TBUtilsTest.PbEncodeFieldsValidMessage]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_tb_utils.cpp:12]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[TBUtilsTest.PbEncodeFieldsNullPointers]=]  /home/dev/dev/tesla-ble/build4/tests/test_tb_utils [==[--gtest_filter=TBUtilsTest.PbEncodeFieldsNullPointers]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[TBUtilsTest.PbEncodeFieldsNullPointers]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_tb_utils.cpp:31]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[TBUtilsTest.PbEncodeFieldsUniversalMessage]=]  /home/dev/dev/tesla-ble/build4/tests/test_tb_utils [==[--gtest_filter=TBUtilsTest.PbEncodeFieldsUniversalMessage]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[TBUtilsTest.PbEncodeFieldsUniversalMessage]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_tb_utils.cpp:53]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[TBUtilsTest.FormatHexBasic]=]  /home/dev/dev/tesla-ble/build4/tests/test_tb_utils [==[--gtest_filter=TBUtilsTest.FormatHexBasic]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[TBUtilsTest.FormatHexBasic]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_tb_utils.cpp:74]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[TBUtilsTest.FormatHexEmptyData]=]  /home/dev/dev/tesla-ble/build4/tests/test_tb_utils [==[--gtest_filter=TBUtilsTest.FormatHexEmptyData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[TBUtilsTest.FormatHexEmptyData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_tb_utils.cpp:81]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[TBUtilsTest.FormatHexSingleByte]=]  /home/dev/dev/tesla-ble/build4/tests/test_tb_utils [==[--gtest_filter=TBUtilsTest.FormatHexSingleByte]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[TBUtilsTest.FormatHexSingleByte]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_tb_utils.cpp:90]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[TBUtilsTest.FormatHexAllZeros]=]  /home/dev/dev/tesla-ble/build4/tests/test_tb_utils [==[--gtest_filter=TBUtilsTest.FormatHexAllZeros]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[TBUtilsTest.FormatHexAllZeros]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_tb_utils.cpp:97]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[TBUtilsTest.FormatHexLargeData]=]  /home/dev/dev/tesla-ble/build4/tests/test_tb_utils [==[--gtest_filter=TBUtilsTest.FormatHexLargeData]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[TBUtilsTest.FormatHexLargeData]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_tb_utils.cpp:104]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_tb_utils_TESTS [==[TBUtilsTest.PbEncodeFieldsValidMessage]==] [==[TBUtilsTest.PbEncodeFieldsNullPointers]==] [==[TBUtilsTest.PbEncodeFieldsUniversalMessage]==] [==[TBUtilsTest.FormatHexBasic]==] [==[TBUtilsTest.FormatHexEmptyData]==] [==[TBUtilsTest.FormatHexSingleByte]==] [==[TBUtilsTest.FormatHexAllZeros]==] [==[TBUtilsTest.FormatHexLargeData]==])
