add_test([=[KeyGenerationTest.CreatePrivateKeyGeneratesValidKey]=]  /home/dev/dev/tesla-ble/build4/tests/test_key_generation [==[--gtest_filter=KeyGenerationTest.CreatePrivateKeyGeneratesValidKey]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[KeyGenerationTest.CreatePrivateKeyGeneratesValidKey]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_key_generation.cpp:20]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[KeyGenerationTest.LoadValidPrivateKey]=]  /home/dev/dev/tesla-ble/build4/tests/test_key_generation [==[--gtest_filter=KeyGenerationTest.LoadValidPrivateKey]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[KeyGenerationTest.LoadValidPrivateKey]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_key_generation.cpp:33]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[KeyGenerationTest.LoadInvalidPrivateKeyFails]=]  /home/dev/dev/tesla-ble/build4/tests/test_key_generation [==[--gtest_filter=KeyGenerationTest.LoadInvalidPrivateKeyFails]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[KeyGenerationTest.LoadInvalidPrivateKeyFails]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_key_generation.cpp:40]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[KeyGenerationTest.LoadEmptyPrivateKeyFails]=]  /home/dev/dev/tesla-ble/build4/tests/test_key_generation [==[--gtest_filter=KeyGenerationTest.LoadEmptyPrivateKeyFails]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[KeyGenerationTest.LoadEmptyPrivateKeyFails]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_key_generation.cpp:65]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[KeyGenerationTest.GetPrivateKeyWithoutLoadingFails]=]  /home/dev/dev/tesla-ble/build4/tests/test_key_generation [==[--gtest_filter=KeyGenerationTest.GetPrivateKeyWithoutLoadingFails]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[KeyGenerationTest.GetPrivateKeyWithoutLoadingFails]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_key_generation.cpp:70]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[KeyGenerationTest.GetPrivateKeyWithInsufficientBufferFails]=]  /home/dev/dev/tesla-ble/build4/tests/test_key_generation [==[--gtest_filter=KeyGenerationTest.GetPrivateKeyWithInsufficientBufferFails]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[KeyGenerationTest.GetPrivateKeyWithInsufficientBufferFails]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_key_generation.cpp:77]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[KeyGenerationTest.RepeatedKeyGenerationWorks]=]  /home/dev/dev/tesla-ble/build4/tests/test_key_generation [==[--gtest_filter=KeyGenerationTest.RepeatedKeyGenerationWorks]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[KeyGenerationTest.RepeatedKeyGenerationWorks]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_key_generation.cpp:91]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_key_generation_TESTS [==[KeyGenerationTest.CreatePrivateKeyGeneratesValidKey]==] [==[KeyGenerationTest.LoadValidPrivateKey]==] [==[KeyGenerationTest.LoadInvalidPrivateKeyFails]==] [==[KeyGenerationTest.LoadEmptyPrivateKeyFails]==] [==[KeyGenerationTest.GetPrivateKeyWithoutLoadingFails]==] [==[KeyGenerationTest.GetPrivateKeyWithInsufficientBufferFails]==] [==[KeyGenerationTest.RepeatedKeyGenerationWorks]==])
