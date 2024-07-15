#ifndef TESLA_BLE_SESSION_H
#define TESLA_BLE_SESSION_H

#include <pb.h>
#include "universal_message.pb.h"
#include "mbedtls/ecp.h"

namespace TeslaBLE
{
  // SharedKeySizeBytes is the length of the cryptographic key shared by a Signer and a Verifier.
  const size_t SharedKeySizeBytes = 16;

  // // ECDHPrivateKey represents a local private key.
  // class ECDHPrivateKey
  // {
  // public:
  //   virtual Session Exchange(const std::vector<unsigned char>&remotePublicBytes) = 0;
  //   virtual std::vector<unsigned char> PublicBytes() = 0;
  // };

  // class Session : public ECDHPrivateKey
  // {
  // public:
  //   Session Exchange(const std::vector<unsigned char>& remotePublicBytes) override;
  //   std::vector<unsigned char> PublicBytes() override;
  // };

  // Session Session::Exchange(const std::vector<unsigned char>& remotePublicBytes)
  // {
  //   // Implementation of the Exchange function
  // }

  // std::vector<unsigned char> Session::PublicBytes()
  // {
  //   // Implementation of the PublicBytes function
  // }

  class Session
  {
  private:
    // mbedtls_pk_context private_key_context_;
    // mbedtls_ecp_keypair tesla_key_;
    // mbedtls_ecdh_context ecdh_context_;
    // mbedtls_ctr_drbg_context drbg_context_;
    // unsigned char shared_secret_[MBEDTLS_ECP_MAX_BYTES];
    // unsigned char key_id_[4];
    // unsigned char public_key_[MBEDTLS_ECP_MAX_BYTES];

    // key         []byte
    // localPublic []byte
    

    pb_byte_t key[SharedKeySizeBytes];
    pb_byte_t localPublic[MBEDTLS_ECP_MAX_BYTES];
    size_t public_key_size_ = 0;

// func (n *NativeECDHKey) Exchange(publicBytes []byte) (Session, error) {
// 	var err error
// 	sharedSecret, err := n.sharedSecret(publicBytes)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// SHA1 is used to maintain compatibility with existing vehicle code, and
// 	// is safe to use in this context since we're just mapping a pseudo-random
// 	// curve point into a pseudo-random bit string.  Collision resistance isn't
// 	// needed.
// 	digest := sha1.Sum(sharedSecret)
// 	var session NativeSession
// 	session.key = digest[:SharedKeySizeBytes]

// 	block, err := aes.NewCipher(session.key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if session.gcm, err = cipher.NewGCM(block); err != nil {
// 		return nil, err
// 	}
// 	session.localPublic = n.PublicBytes()
// 	return &session, nil
// }

  public:
    bool isAuthenticated = false;
    void setIsAuthenticated(bool isAuthenticated);
    void setPublicKey(unsigned char *public_key, size_t public_key_size);
    unsigned char *getPublicKey();
    size_t getPublicKeySize();
  };
} // namespace TeslaBLE
#endif // TESLA_BLE_SESSION_H
