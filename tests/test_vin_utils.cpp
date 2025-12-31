#include <gtest/gtest.h>
#include <vin_utils.h>

using namespace TeslaBLE;

class VINUtilsTest : public ::testing::Test {};

// getVINAdvertisementName
TEST_F(VINUtilsTest, GetVINAdvertisementNameGeneratesValidFormat) {
    std::string name = getVINAdvertisementName("5YJS0000000000000");
    
    ASSERT_EQ(name.length(), 18);
    EXPECT_EQ(name[0], 'S');
    EXPECT_EQ(name[17], 'C');
    
    // Middle 16 chars should be valid hex
    for (int i = 1; i < 17; i++) {
        EXPECT_TRUE(isxdigit(name[i]));
    }
}

TEST_F(VINUtilsTest, GetVINAdvertisementNameDeterministic) {
    const char* vin = "5YJS0000000000000";
    std::string name1 = getVINAdvertisementName(vin);
    std::string name2 = getVINAdvertisementName(vin);
    
    EXPECT_EQ(name1, name2);
}

TEST_F(VINUtilsTest, GetVINAdvertisementNameDifferentVINsProduceDifferentNames) {
    std::string name1 = getVINAdvertisementName("5YJS0000000000000");
    std::string name2 = getVINAdvertisementName("5YJS0000000000001");
    
    EXPECT_NE(name1, name2);
}

TEST_F(VINUtilsTest, GetVINAdvertisementNameHandlesStringInput) {
    std::string name = getVINAdvertisementName(std::string("5YJS0000000000000"));
    EXPECT_EQ(name.length(), 18);
}

TEST_F(VINUtilsTest, GetVINAdvertisementNameRejectsInvalidInput) {
    EXPECT_TRUE(getVINAdvertisementName(nullptr).empty());
    EXPECT_TRUE(getVINAdvertisementName("").empty());
    EXPECT_TRUE(getVINAdvertisementName("SHORT").empty());
    EXPECT_TRUE(getVINAdvertisementName("5YJS0000000000000EXTRA").empty());
}

// isTeslaVehicleName
TEST_F(VINUtilsTest, IsTeslaVehicleNameValidatesFormat) {
    // Should accept valid Tesla names
    EXPECT_TRUE(isTeslaVehicleName("S0000000000000000C"));
    EXPECT_TRUE(isTeslaVehicleName("SffffffffffffffffC"));
    EXPECT_TRUE(isTeslaVehicleName("SaAbBcCdDeEfFaAbBC"));
}

TEST_F(VINUtilsTest, IsTeslaVehicleNameHandlesStringInput) {
    EXPECT_TRUE(isTeslaVehicleName(std::string("S0000000000000000C")));
}

TEST_F(VINUtilsTest, IsTeslaVehicleNameRejectsInvalidFormat) {
    EXPECT_FALSE(isTeslaVehicleName(nullptr));
    EXPECT_FALSE(isTeslaVehicleName(""));
    EXPECT_FALSE(isTeslaVehicleName("invalid"));
    
    // Wrong start character
    EXPECT_FALSE(isTeslaVehicleName("T0000000000000000C"));
    
    // Wrong end character
    EXPECT_FALSE(isTeslaVehicleName("S0000000000000000D"));
    
    // Wrong length
    EXPECT_FALSE(isTeslaVehicleName("S000000000000000C"));
    EXPECT_FALSE(isTeslaVehicleName("S00000000000000000C"));
    
    // Non-hex characters
    EXPECT_FALSE(isTeslaVehicleName("SG000000000000000C"));
    EXPECT_FALSE(isTeslaVehicleName("S0000000X0000000C"));
}

// matchesVIN
TEST_F(VINUtilsTest, MatchesVINVerifiesVINDeviceNamePairing) {
    std::string name = getVINAdvertisementName("5YJS0000000000000");
    
    EXPECT_TRUE(matchesVIN(name, "5YJS0000000000000"));
    EXPECT_FALSE(matchesVIN(name, "5YJS0000000000001"));
}

TEST_F(VINUtilsTest, MatchesVINHandlesStringInput) {
    std::string name = getVINAdvertisementName("5YJS0000000000000");
    std::string vin = "5YJS0000000000000";
    
    EXPECT_TRUE(matchesVIN(name, vin));
}

TEST_F(VINUtilsTest, MatchesVINRejectsInvalidInput) {
    const char* valid_vin = "5YJS0000000000000";
    
    EXPECT_FALSE(matchesVIN(nullptr, valid_vin));
    EXPECT_FALSE(matchesVIN("invalid", valid_vin));
    EXPECT_FALSE(matchesVIN("S0000000000000000C", nullptr));
}

// Integration: roundtrip VIN to name and back
TEST_F(VINUtilsTest, RoundtripVINGenerationAndValidation) {
    const char* vins[] = {
        "5YJS0000000000000",
        "5Y3E1EA5JF0000001",
        "5TDJXRFH4LS123456",
    };
    
    for (const char* vin : vins) {
        std::string name = getVINAdvertisementName(vin);
        
        // Generated name should be valid Tesla format
        EXPECT_TRUE(isTeslaVehicleName(name));
        
        // Name should match the original VIN
        EXPECT_TRUE(matchesVIN(name, vin));
    }
}
