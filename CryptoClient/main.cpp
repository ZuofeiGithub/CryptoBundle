#include <iostream>
#include "cryptotools.h"
#include "bytearray.h"

int main(){
    ByteArray valid_data = "{\"secure_code\":\"8ryh439rh4rn3443\"}";
    ByteArray invalid_data = "{\"secure_code\":\"7RYh439rh4rn3443\"}";

    std::cout << "generate hash... " << std::flush<<std::endl;
    AnyMap algorithm_params;
    algorithm_params.insert({"workload",12});
    ByteArray hash = CryptoTools::generateHash(BCRYPT_HASH, valid_data, algorithm_params);
    std::cout << "done. Hash: " <<hash.data()<< std::endl;

    auto tokens =hash.splite('$');
    std::cout << "workload: " <<tokens[1].data()<< std::endl;

    std::cout << "checking right password: " << std::flush
              << CryptoTools::validateDataHash(BCRYPT_HASH, valid_data, hash) << std::endl;

    std::cout << "checking wrong password: " << std::flush
              << CryptoTools::validateDataHash(BCRYPT_HASH, invalid_data, hash) << std::endl<< std::endl;

    return 0;
}
