#include <gtest/gtest.h>
#include <vin_utils.h>

using namespace TeslaBLE;

class VINUtilsTest : public ::testing::Test {};

// get_vin_advertisement_name
TEST_F(VINUtilsTest, GetVINAdvertisementNameGeneratesValidFormat) {
  std::string name = get_vin_advertisement_name("5YJS0000000000000");

  ASSERT_EQ(name.length(), 18);
  EXPECT_EQ(name[0], 'S');
  EXPECT_EQ(name[17], 'C');

  // Middle 16 chars should be valid hex
  for (int i = 1; i < 17; ++i) {
    EXPECT_TRUE(isxdigit(static_cast<unsigned char>(name[i])));
  }
}

TEST_F(VINUtilsTest, GetVINAdvertisementNameDeterministic) {
  const char *vin = "5YJS0000000000000";
  std::string name1 = get_vin_advertisement_name(vin);
  std::string name2 = get_vin_advertisement_name(vin);

  EXPECT_EQ(name1, name2);
}

TEST_F(VINUtilsTest, GetVINAdvertisementNameDifferentVINsProduceDifferentNames) {
  std::string name1 = get_vin_advertisement_name("5YJS0000000000000");
  std::string name2 = get_vin_advertisement_name("5YJS0000000000001");

  EXPECT_NE(name1, name2);
}

TEST_F(VINUtilsTest, GetVINAdvertisementNameHandlesStringInput) {
  std::string name = get_vin_advertisement_name(std::string("5YJS0000000000000"));
  EXPECT_EQ(name.length(), 18);
}

TEST_F(VINUtilsTest, GetVINAdvertisementNameRejectsInvalidInput) {
  EXPECT_TRUE(get_vin_advertisement_name(nullptr).empty());
  EXPECT_TRUE(get_vin_advertisement_name("").empty());
  EXPECT_TRUE(get_vin_advertisement_name("SHORT").empty());
  EXPECT_TRUE(get_vin_advertisement_name("5YJS0000000000000EXTRA").empty());
}

// is_tesla_vehicle_name
TEST_F(VINUtilsTest, IsTeslaVehicleNameValidatesFormat) {
  // Should accept valid Tesla names
  EXPECT_TRUE(is_tesla_vehicle_name("S0000000000000000C"));
  EXPECT_TRUE(is_tesla_vehicle_name("SffffffffffffffffC"));
  EXPECT_TRUE(is_tesla_vehicle_name("SaAbBcCdDeEfFaAbBC"));
}

TEST_F(VINUtilsTest, IsTeslaVehicleNameHandlesStringInput) {
  EXPECT_TRUE(is_tesla_vehicle_name(std::string("S0000000000000000C")));
}

TEST_F(VINUtilsTest, IsTeslaVehicleNameRejectsInvalidFormat) {
  EXPECT_FALSE(is_tesla_vehicle_name(nullptr));
  EXPECT_FALSE(is_tesla_vehicle_name(""));
  EXPECT_FALSE(is_tesla_vehicle_name("invalid"));

  // Wrong start character
  EXPECT_FALSE(is_tesla_vehicle_name("T0000000000000000C"));

  // Wrong end character
  EXPECT_FALSE(is_tesla_vehicle_name("S0000000000000000D"));

  // Wrong length
  EXPECT_FALSE(is_tesla_vehicle_name("S000000000000000C"));
  EXPECT_FALSE(is_tesla_vehicle_name("S00000000000000000C"));

  // Non-hex characters
  EXPECT_FALSE(is_tesla_vehicle_name("SG000000000000000C"));
  EXPECT_FALSE(is_tesla_vehicle_name("S0000000X0000000C"));
}

// matches_vin
TEST_F(VINUtilsTest, MatchesVINVerifiesVINDeviceNamePairing) {
  std::string name = get_vin_advertisement_name("5YJS0000000000000");

  EXPECT_TRUE(matches_vin(name, "5YJS0000000000000"));
  EXPECT_FALSE(matches_vin(name, "5YJS0000000000001"));
}

TEST_F(VINUtilsTest, MatchesVINHandlesStringInput) {
  std::string name = get_vin_advertisement_name("5YJS0000000000000");
  std::string vin = "5YJS0000000000000";

  EXPECT_TRUE(matches_vin(name, vin));
}

TEST_F(VINUtilsTest, MatchesVINRejectsInvalidInput) {
  const char *valid_vin = "5YJS0000000000000";

  EXPECT_FALSE(matches_vin(nullptr, valid_vin));
  EXPECT_FALSE(matches_vin("invalid", valid_vin));
  EXPECT_FALSE(matches_vin("S0000000000000000C", nullptr));
}

// Integration: roundtrip VIN to name and back
TEST_F(VINUtilsTest, RoundtripVINGenerationAndValidation) {
  const char *vins[] = {
      "5YJS0000000000000",
      "5Y3E1EA5JF0000001",
      "5TDJXRFH4LS123456",
  };

  for (const char *vin : vins) {
    std::string name = get_vin_advertisement_name(vin);

    // Generated name should be valid Tesla format
    EXPECT_TRUE(is_tesla_vehicle_name(name));

    // Name should match the original VIN
    EXPECT_TRUE(matches_vin(name, vin));
  }
}
