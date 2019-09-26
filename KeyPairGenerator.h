#ifndef KEYPAIRGENERATOR_H
#define KEYPAIRGENERATOR_H

#include <Arduino.h>
#include <SPIFFS.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"

class KeyPairGenerator{
public:
  //Generate and store a private/public key pair RSA 2048 bit
  bool generateKeyPair(char* publicKeyFilePath, char* privateKeyFilePath);

private:
  void cleanup();

};
#endif
