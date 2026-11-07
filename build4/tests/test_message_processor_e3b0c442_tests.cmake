add_test([=[MessageProcessorTest.EmptyQueueProcessesNothing]=]  /home/dev/dev/tesla-ble/build4/tests/test_message_processor [==[--gtest_filter=MessageProcessorTest.EmptyQueueProcessesNothing]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[MessageProcessorTest.EmptyQueueProcessesNothing]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_message_processor.cpp:16]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[MessageProcessorTest.ProcessesQueuedMessagesInOrder]=]  /home/dev/dev/tesla-ble/build4/tests/test_message_processor [==[--gtest_filter=MessageProcessorTest.ProcessesQueuedMessagesInOrder]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[MessageProcessorTest.ProcessesQueuedMessagesInOrder]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_message_processor.cpp:23]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[MessageProcessorTest.MessagesQueuedWhileProcessingWaitForTheNextCall]=]  /home/dev/dev/tesla-ble/build4/tests/test_message_processor [==[--gtest_filter=MessageProcessorTest.MessagesQueuedWhileProcessingWaitForTheNextCall]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[MessageProcessorTest.MessagesQueuedWhileProcessingWaitForTheNextCall]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_message_processor.cpp:34]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[MessageProcessorTest.BacklogIsBoundedDroppingTheOldest]=]  /home/dev/dev/tesla-ble/build4/tests/test_message_processor [==[--gtest_filter=MessageProcessorTest.BacklogIsBoundedDroppingTheOldest]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[MessageProcessorTest.BacklogIsBoundedDroppingTheOldest]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_message_processor.cpp:54]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_message_processor_TESTS [==[MessageProcessorTest.EmptyQueueProcessesNothing]==] [==[MessageProcessorTest.ProcessesQueuedMessagesInOrder]==] [==[MessageProcessorTest.MessagesQueuedWhileProcessingWaitForTheNextCall]==] [==[MessageProcessorTest.BacklogIsBoundedDroppingTheOldest]==])
