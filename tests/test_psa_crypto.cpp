/**
 * @file test_psa_crypto.cpp
 * @brief Checks the PSA Crypto implementation against the protocol vectors and
 *        against the legacy Mbed TLS 3.x APIs it replaced.
 *
 * The library uses PSA so it builds with Mbed TLS 3.6 (ESP-IDF 5.x) and
 * Mbed TLS 4.x (ESP-IDF 6.x). The host build links Mbed TLS 3.6, so the
 * legacy APIs are still available here as a reference implementation.
 */

#include <gtest/gtest.h>
#include <crypto_context.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <psa/crypto.h>
#include <cstring>
#include <string>
#include "test_constants.h"

namespace TeslaBLE {
namespace {

std::vector<uint8_t> from_hex(const std::string &hex) {
  std::vector<uint8_t> out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
  }
  return out;
}

std::string to_hex(const uint8_t *data, size_t length) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < length; ++i) {
    out += digits[data[i] >> 4];
    out += digits[data[i] & 0x0f];
  }
  return out;
}

int legacy_rng(void * /*unused*/, unsigned char *output, size_t length) {
  return psa_generate_random(output, length) == PSA_SUCCESS ? 0 : -1;
}

// Protocol spec example: "Turn HVAC on" with its metadata.
const char *const PLAINTEXT_HEX = "120452020801";
const char *const METADATA_HEX =
    "000105010103021135594a333031323334353637383941424303104c463f9cc0d3d26906e982ed224adde6040400000a5f050400000007ff";
const uint8_t NONCE[12] = {0xdb, 0xf7, 0x94, 0x47, 0xfa, 0x15, 0x66, 0x74, 0xda, 0xe1, 0xca, 0xed};

}  // namespace

class PsaCryptoTest : public ::testing::Test {
 protected:
  void SetUp() override { ASSERT_TRUE(CryptoUtils::ensure_psa_initialized()); }
};

TEST_F(PsaCryptoTest, Sha1KnownAnswer) {
  const char *input = "abc";
  uint8_t out[20];
  ASSERT_EQ(CryptoUtils::sha1_hash(reinterpret_cast<const pb_byte_t *>(input), 3, out), TeslaBLE_Status_E_OK);
  EXPECT_EQ(to_hex(out, sizeof(out)), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST_F(PsaCryptoTest, Sha256MatchesLegacy) {
  auto metadata = from_hex(METADATA_HEX);
  uint8_t psa_out[32];
  uint8_t legacy_out[32];
  ASSERT_EQ(CryptoUtils::sha256_hash(metadata.data(), metadata.size(), psa_out), TeslaBLE_Status_E_OK);
  ASSERT_EQ(mbedtls_sha256(metadata.data(), metadata.size(), legacy_out, 0), 0);
  EXPECT_EQ(to_hex(psa_out, 32), to_hex(legacy_out, 32));
}

TEST_F(PsaCryptoTest, SessionInfoKeyMatchesSpec) {
  uint8_t key[32];
  ASSERT_EQ(CryptoUtils::derive_session_info_key(TestConstants::EXPECTED_SESSION_KEY, 16, key, sizeof(key)),
            TeslaBLE_Status_E_OK);
  EXPECT_EQ(to_hex(key, sizeof(key)), "fceb679ee7bca756fcd441bf238bf2f338629b41d9eb9c67be1b32c9672ce300");
}

TEST_F(PsaCryptoTest, HmacMatchesLegacy) {
  auto metadata = from_hex(METADATA_HEX);
  uint8_t psa_out[32];
  uint8_t legacy_out[32];
  ASSERT_EQ(CryptoUtils::hmac_sha256(TestConstants::EXPECTED_SESSION_KEY, 16, metadata.data(), metadata.size(), psa_out,
                                     sizeof(psa_out)),
            TeslaBLE_Status_E_OK);
  ASSERT_EQ(mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), TestConstants::EXPECTED_SESSION_KEY, 16,
                            metadata.data(), metadata.size(), legacy_out),
            0);
  EXPECT_EQ(to_hex(psa_out, 32), to_hex(legacy_out, 32));
}

TEST_F(PsaCryptoTest, AesGcmMatchesLegacyAndRoundTrips) {
  auto plaintext = from_hex(PLAINTEXT_HEX);
  auto metadata = from_hex(METADATA_HEX);
  uint8_t aad[32];
  ASSERT_EQ(CryptoUtils::sha256_hash(metadata.data(), metadata.size(), aad), TeslaBLE_Status_E_OK);

  // PSA
  std::vector<uint8_t> ciphertext(plaintext.size());
  uint8_t tag[16];
  ASSERT_EQ(CryptoUtils::aes_gcm_encrypt(TestConstants::EXPECTED_SESSION_KEY, NONCE, aad, sizeof(aad), plaintext.data(),
                                         plaintext.size(), ciphertext.data(), ciphertext.size(), tag),
            TeslaBLE_Status_E_OK);

  // Legacy reference
  std::vector<uint8_t> legacy_ciphertext(plaintext.size());
  uint8_t legacy_tag[16];
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  ASSERT_EQ(mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, TestConstants::EXPECTED_SESSION_KEY, 128), 0);
  ASSERT_EQ(
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), NONCE, sizeof(NONCE), aad, sizeof(aad),
                                plaintext.data(), legacy_ciphertext.data(), sizeof(legacy_tag), legacy_tag),
      0);
  mbedtls_gcm_free(&gcm);

  EXPECT_EQ(to_hex(ciphertext.data(), ciphertext.size()), to_hex(legacy_ciphertext.data(), legacy_ciphertext.size()));
  EXPECT_EQ(to_hex(tag, 16), to_hex(legacy_tag, 16));

  std::vector<uint8_t> decrypted(plaintext.size());
  ASSERT_EQ(CryptoUtils::aes_gcm_decrypt(TestConstants::EXPECTED_SESSION_KEY, NONCE, aad, sizeof(aad),
                                         ciphertext.data(), ciphertext.size(), tag, decrypted.data(), decrypted.size()),
            TeslaBLE_Status_E_OK);
  EXPECT_EQ(decrypted, plaintext);
}

TEST_F(PsaCryptoTest, AesGcmRejectsTampering) {
  auto plaintext = from_hex(PLAINTEXT_HEX);
  uint8_t aad[32] = {1, 2, 3};
  std::vector<uint8_t> ciphertext(plaintext.size());
  uint8_t tag[16];
  ASSERT_EQ(CryptoUtils::aes_gcm_encrypt(TestConstants::EXPECTED_SESSION_KEY, NONCE, aad, sizeof(aad), plaintext.data(),
                                         plaintext.size(), ciphertext.data(), ciphertext.size(), tag),
            TeslaBLE_Status_E_OK);

  std::vector<uint8_t> out(plaintext.size());

  uint8_t bad_tag[16];
  std::memcpy(bad_tag, tag, 16);
  bad_tag[0] ^= 0x01;
  EXPECT_NE(CryptoUtils::aes_gcm_decrypt(TestConstants::EXPECTED_SESSION_KEY, NONCE, aad, sizeof(aad),
                                         ciphertext.data(), ciphertext.size(), bad_tag, out.data(), out.size()),
            TeslaBLE_Status_E_OK);

  uint8_t bad_aad[32];
  std::memcpy(bad_aad, aad, 32);
  bad_aad[5] ^= 0x80;
  EXPECT_NE(CryptoUtils::aes_gcm_decrypt(TestConstants::EXPECTED_SESSION_KEY, NONCE, bad_aad, sizeof(bad_aad),
                                         ciphertext.data(), ciphertext.size(), tag, out.data(), out.size()),
            TeslaBLE_Status_E_OK);

  ciphertext[0] ^= 0x01;
  EXPECT_NE(CryptoUtils::aes_gcm_decrypt(TestConstants::EXPECTED_SESSION_KEY, NONCE, aad, sizeof(aad),
                                         ciphertext.data(), ciphertext.size(), tag, out.data(), out.size()),
            TeslaBLE_Status_E_OK);
}

// Keys saved by earlier releases must load, and keys saved now must be
// byte-identical to what earlier releases wrote (so a downgrade still works).
TEST_F(PsaCryptoTest, PemStorageMatchesLegacyFormat) {
  const char *pem = TestConstants::CLIENT_PRIVATE_KEY_PEM;
  CryptoContext crypto;
  ASSERT_EQ(crypto.load_private_key(reinterpret_cast<const uint8_t *>(pem), std::strlen(pem) + 1),
            TeslaBLE_Status_E_OK);

  uint8_t pem_out[512];
  size_t pem_out_length = 0;
  ASSERT_EQ(crypto.get_private_key(pem_out, sizeof(pem_out), &pem_out_length), TeslaBLE_Status_E_OK);

  mbedtls_pk_context legacy;
  mbedtls_pk_init(&legacy);
  ASSERT_EQ(mbedtls_pk_parse_key(&legacy, reinterpret_cast<const uint8_t *>(pem), std::strlen(pem) + 1, nullptr, 0,
                                 legacy_rng, nullptr),
            0);
  uint8_t legacy_pem[512];
  ASSERT_EQ(mbedtls_pk_write_key_pem(&legacy, legacy_pem, sizeof(legacy_pem)), 0);
  mbedtls_pk_free(&legacy);

  EXPECT_STREQ(reinterpret_cast<char *>(pem_out), reinterpret_cast<char *>(legacy_pem));

  uint8_t public_key[65];
  size_t public_key_length = sizeof(public_key);
  ASSERT_EQ(crypto.generate_public_key(public_key, &public_key_length), TeslaBLE_Status_E_OK);
  ASSERT_EQ(public_key_length, 65u);
  EXPECT_EQ(to_hex(public_key, 65), to_hex(TestConstants::EXPECTED_CLIENT_PUBLIC_KEY, 65));
}

TEST_F(PsaCryptoTest, GeneratedKeyRoundTripsAndAgrees) {
  CryptoContext a;
  CryptoContext b;
  ASSERT_EQ(a.create_private_key(), TeslaBLE_Status_E_OK);
  ASSERT_EQ(b.create_private_key(), TeslaBLE_Status_E_OK);

  uint8_t pub_a[65];
  uint8_t pub_b[65];
  size_t len_a = sizeof(pub_a);
  size_t len_b = sizeof(pub_b);
  ASSERT_EQ(a.generate_public_key(pub_a, &len_a), TeslaBLE_Status_E_OK);
  ASSERT_EQ(b.generate_public_key(pub_b, &len_b), TeslaBLE_Status_E_OK);
  ASSERT_EQ(len_a, 65u);
  EXPECT_EQ(pub_a[0], 0x04);

  uint8_t k_ab[16];
  uint8_t k_ba[16];
  ASSERT_EQ(a.perform_tesla_ecdh(pub_b, 65, k_ab), TeslaBLE_Status_E_OK);
  ASSERT_EQ(b.perform_tesla_ecdh(pub_a, 65, k_ba), TeslaBLE_Status_E_OK);
  EXPECT_EQ(to_hex(k_ab, 16), to_hex(k_ba, 16));

  // Save and reload: same public key, and the PEM still parses with the legacy API.
  uint8_t pem[512];
  size_t pem_length = 0;
  ASSERT_EQ(a.get_private_key(pem, sizeof(pem), &pem_length), TeslaBLE_Status_E_OK);

  CryptoContext reloaded;
  ASSERT_EQ(reloaded.load_private_key(pem, pem_length), TeslaBLE_Status_E_OK);
  uint8_t pub_reloaded[65];
  size_t len_reloaded = sizeof(pub_reloaded);
  ASSERT_EQ(reloaded.generate_public_key(pub_reloaded, &len_reloaded), TeslaBLE_Status_E_OK);
  EXPECT_EQ(to_hex(pub_a, 65), to_hex(pub_reloaded, 65));

  mbedtls_pk_context legacy;
  mbedtls_pk_init(&legacy);
  EXPECT_EQ(mbedtls_pk_parse_key(&legacy, pem, pem_length, nullptr, 0, legacy_rng, nullptr), 0);
  mbedtls_pk_free(&legacy);
}

TEST_F(PsaCryptoTest, MoveTransfersKeyOwnership) {
  CryptoContext a;
  ASSERT_EQ(a.create_private_key(), TeslaBLE_Status_E_OK);
  CryptoContext b(std::move(a));
  EXPECT_FALSE(a.is_private_key_initialized());  // NOLINT(bugprone-use-after-move)
  EXPECT_TRUE(b.is_private_key_initialized());

  CryptoContext c;
  ASSERT_EQ(c.create_private_key(), TeslaBLE_Status_E_OK);
  c = std::move(b);
  EXPECT_TRUE(c.is_private_key_initialized());
  EXPECT_FALSE(b.is_private_key_initialized());  // NOLINT(bugprone-use-after-move)
}

TEST_F(PsaCryptoTest, RejectsNonP256Key) {
  // secp384r1 key: valid EC PEM, wrong curve for the Tesla protocol.
  const char *p384_pem = "-----BEGIN EC PRIVATE KEY-----\n"
                         "MIGkAgEBBDB1hRomYeZD+2n7SJJpwjKb9rUHD+BUAfBFdNxB4fvw4+Pq03C03EoG\n"
                         "VSi0U4ky9N+gBwYFK4EEACKhZANiAAS9KHI/bf79+6JsR2M44bAFJM6IRDU5WFGx\n"
                         "3U+GDFQZyItLjhut0gCFkqNeYlEpqAMHKmUl76uFfAXVri8miRQgH2nzgQwiyHlL\n"
                         "z6GTXOBJpMvehz8FtoCZ2b0wto3I/Ms=\n"
                         "-----END EC PRIVATE KEY-----";
  CryptoContext crypto;
  EXPECT_NE(crypto.load_private_key(reinterpret_cast<const uint8_t *>(p384_pem), std::strlen(p384_pem) + 1),
            TeslaBLE_Status_E_OK);
  EXPECT_FALSE(crypto.is_private_key_initialized());
}

}  // namespace TeslaBLE
