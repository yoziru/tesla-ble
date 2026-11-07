add_test([=[ChargingPower.FieldReportsAndSyntheticSupplyVariants]=]  /home/dev/dev/tesla-ble/build4/tests/test_charging_power [==[--gtest_filter=ChargingPower.FieldReportsAndSyntheticSupplyVariants]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ChargingPower.FieldReportsAndSyntheticSupplyVariants]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_charging_power.cpp:34]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ChargingPower.AmbiguityAndOutliersFallBackWithoutPoisoningLaterSamples]=]  /home/dev/dev/tesla-ble/build4/tests/test_charging_power [==[--gtest_filter=ChargingPower.AmbiguityAndOutliersFallBackWithoutPoisoningLaterSamples]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ChargingPower.AmbiguityAndOutliersFallBackWithoutPoisoningLaterSamples]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_charging_power.cpp:70]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ChargingPower.CurrentChangesAndAmbiguousVoltageReferenceRequireFreshEvidence]=]  /home/dev/dev/tesla-ble/build4/tests/test_charging_power [==[--gtest_filter=ChargingPower.CurrentChangesAndAmbiguousVoltageReferenceRequireFreshEvidence]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ChargingPower.CurrentChangesAndAmbiguousVoltageReferenceRequireFreshEvidence]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_charging_power.cpp:90]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ChargingPower.MissingInvalidAndDcReadingsNeverReuseAcInputs]=]  /home/dev/dev/tesla-ble/build4/tests/test_charging_power [==[--gtest_filter=ChargingPower.MissingInvalidAndDcReadingsNeverReuseAcInputs]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ChargingPower.MissingInvalidAndDcReadingsNeverReuseAcInputs]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_charging_power.cpp:107]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ChargingPower.CableClassificationDoesNotMistakeDcOrUnknownForAc]=]  /home/dev/dev/tesla-ble/build4/tests/test_charging_power [==[--gtest_filter=ChargingPower.CableClassificationDoesNotMistakeDcOrUnknownForAc]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ChargingPower.CableClassificationDoesNotMistakeDcOrUnknownForAc]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_charging_power.cpp:159]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ChargingPower.UnplugAndNonChargingStatesResetLearning]=]  /home/dev/dev/tesla-ble/build4/tests/test_charging_power [==[--gtest_filter=ChargingPower.UnplugAndNonChargingStatesResetLearning]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ChargingPower.UnplugAndNonChargingStatesResetLearning]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_charging_power.cpp:186]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_charging_power_TESTS [==[ChargingPower.FieldReportsAndSyntheticSupplyVariants]==] [==[ChargingPower.AmbiguityAndOutliersFallBackWithoutPoisoningLaterSamples]==] [==[ChargingPower.CurrentChangesAndAmbiguousVoltageReferenceRequireFreshEvidence]==] [==[ChargingPower.MissingInvalidAndDcReadingsNeverReuseAcInputs]==] [==[ChargingPower.CableClassificationDoesNotMistakeDcOrUnknownForAc]==] [==[ChargingPower.UnplugAndNonChargingStatesResetLearning]==])
