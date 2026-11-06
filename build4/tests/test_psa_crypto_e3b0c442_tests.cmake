add_test([=[PsaCryptoTest.Sha1KnownAnswer]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.Sha1KnownAnswer]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.Sha1KnownAnswer]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:66]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.Sha256MatchesLegacy]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.Sha256MatchesLegacy]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.Sha256MatchesLegacy]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:73]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.SessionInfoKeyMatchesSpec]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.SessionInfoKeyMatchesSpec]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.SessionInfoKeyMatchesSpec]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:80]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.HmacMatchesLegacy]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.HmacMatchesLegacy]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.HmacMatchesLegacy]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:87]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.AesGcmMatchesLegacyAndRoundTrips]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.AesGcmMatchesLegacyAndRoundTrips]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.AesGcmMatchesLegacyAndRoundTrips]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:96]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.AesGcmRejectsTampering]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.AesGcmRejectsTampering]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.AesGcmRejectsTampering]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:120]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.PemStorageMatchesLegacyFormat]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.PemStorageMatchesLegacyFormat]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.PemStorageMatchesLegacyFormat]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:153]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.GeneratedKeyRoundTripsAndAgrees]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.GeneratedKeyRoundTripsAndAgrees]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.GeneratedKeyRoundTripsAndAgrees]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:179]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.MoveTransfersKeyOwnership]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.MoveTransfersKeyOwnership]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.MoveTransfersKeyOwnership]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:218]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[PsaCryptoTest.RejectsNonP256Key]=]  /home/dev/dev/tesla-ble/build4/tests/test_psa_crypto [==[--gtest_filter=PsaCryptoTest.RejectsNonP256Key]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[PsaCryptoTest.RejectsNonP256Key]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/dev/dev/tesla-ble/tests/test_psa_crypto.cpp:232]==]
    WORKING_DIRECTORY [==[/home/dev/dev/tesla-ble/build4/tests]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(test_psa_crypto_TESTS [==[PsaCryptoTest.Sha1KnownAnswer]==] [==[PsaCryptoTest.Sha256MatchesLegacy]==] [==[PsaCryptoTest.SessionInfoKeyMatchesSpec]==] [==[PsaCryptoTest.HmacMatchesLegacy]==] [==[PsaCryptoTest.AesGcmMatchesLegacyAndRoundTrips]==] [==[PsaCryptoTest.AesGcmRejectsTampering]==] [==[PsaCryptoTest.PemStorageMatchesLegacyFormat]==] [==[PsaCryptoTest.GeneratedKeyRoundTripsAndAgrees]==] [==[PsaCryptoTest.MoveTransfersKeyOwnership]==] [==[PsaCryptoTest.RejectsNonP256Key]==])
