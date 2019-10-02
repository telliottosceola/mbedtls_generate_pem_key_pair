# mbedtls_generate_pem_key_pair
This library was designed to run on ESP32 Arduino.  It simply generates a key pair using mbedtls in pem format and stores them as new files in SPIFFS at the directories passed to the generateKeyPair function.

Note: If you are limited in Flash memory consider altering the library to store keys in DER format as this will reduce file size.

Also see this conversation on the ARM embed forum to review the discussion this library was created around:
https://forums.mbed.com/t/generating-private-public-key-pair-in-pem-format/5642/13
