add_test([=[ADBufferConstructionTest.RequestMetadataFormat]=]  /home/dev/dev/tesla-ble/build4/tests/test_ad_buffer_construction [==[--gtest_filter=ADBufferConstructionTest.RequestMetadataFormat]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ADBufferConstructionTest.RequestMetadataFormat]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_ad_buffer_construction.cpp:51]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ADBufferConstructionTest.ResponseMetadataFormat]=]  /home/dev/dev/tesla-ble/build4/tests/test_ad_buffer_construction [==[--gtest_filter=ADBufferConstructionTest.ResponseMetadataFormat]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ADBufferConstructionTest.ResponseMetadataFormat]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_ad_buffer_construction.cpp:106]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ADBufferConstructionTest.FlagsConditionalInclusion]=]  /home/dev/dev/tesla-ble/build4/tests/test_ad_buffer_construction [==[--gtest_filter=ADBufferConstructionTest.FlagsConditionalInclusion]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ADBufferConstructionTest.FlagsConditionalInclusion]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_ad_buffer_construction.cpp:179]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ADBufferConstructionTest.ResponseAlwaysIncludesFlags]=]  /home/dev/dev/tesla-ble/build4/tests/test_ad_buffer_construction [==[--gtest_filter=ADBufferConstructionTest.ResponseAlwaysIncludesFlags]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ADBufferConstructionTest.ResponseAlwaysIncludesFlags]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_ad_buffer_construction.cpp:240]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ADBufferConstructionTest.DifferentDomainsProduceDifferentBuffers]=]  /home/dev/dev/tesla-ble/build4/tests/test_ad_buffer_construction [==[--gtest_filter=ADBufferConstructionTest.DifferentDomainsProduceDifferentBuffers]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ADBufferConstructionTest.DifferentDomainsProduceDifferentBuffers]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_ad_buffer_construction.cpp:267]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ADBufferConstructionTest.TerminalByteAlwaysPresent]=]  /home/dev/dev/tesla-ble/build4/tests/test_ad_buffer_construction [==[--gtest_filter=ADBufferConstructionTest.TerminalByteAlwaysPresent]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ADBufferConstructionTest.TerminalByteAlwaysPresent]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_ad_buffer_construction.cpp:288]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ADBufferConstructionTest.InvalidParametersReturnError]=]  /home/dev/dev/tesla-ble/build4/tests/test_ad_buffer_construction [==[--gtest_filter=ADBufferConstructionTest.InvalidParametersReturnError]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ADBufferConstructionTest.InvalidParametersReturnError]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_ad_buffer_construction.cpp:303]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ADBufferConstructionTest.RequestHashDomainDifferences]=]  /home/dev/dev/tesla-ble/build4/tests/test_ad_buffer_construction [==[--gtest_filter=ADBufferConstructionTest.RequestHashDomainDifferences]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ADBufferConstructionTest.RequestHashDomainDifferences]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_ad_buffer_construction.cpp:324]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_ad_buffer_construction_TESTS [==[ADBufferConstructionTest.RequestMetadataFormat]==] [==[ADBufferConstructionTest.ResponseMetadataFormat]==] [==[ADBufferConstructionTest.FlagsConditionalInclusion]==] [==[ADBufferConstructionTest.ResponseAlwaysIncludesFlags]==] [==[ADBufferConstructionTest.DifferentDomainsProduceDifferentBuffers]==] [==[ADBufferConstructionTest.TerminalByteAlwaysPresent]==] [==[ADBufferConstructionTest.InvalidParametersReturnError]==] [==[ADBufferConstructionTest.RequestHashDomainDifferences]==])
