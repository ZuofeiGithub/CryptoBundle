#include <iostream>
#include "cryptotools.h"
#include "bytearray.h"

void cryptotool_test()
{
    ByteArray valid_data   = "{\"HandleProcess\":{\"ProcessType\":\"Wait\",\"ProcessParams\":{\"Delay\":3000}}10";
    ByteArray invalid_data = "{\"HandleProcess\":{\"ProcessType\":\"Wait\",\"ProcessParams\":{\"Delay\":3000}}12";
    std::cout << "generate hash... " << std::flush<<std::endl;
    AnyMap algorithm_params;
    algorithm_params.insert({"workload",12});
    ByteArray hash = CryptoTools::generateHash(BCRYPT_HASH, valid_data, algorithm_params);
    std::cout << "done. Hash: " <<hash.data()<< std::endl;

    auto tokens =hash.split('$');
    std::cout << "workload: " <<tokens[1].data()<< std::endl;

    std::cout << "checking right password: " << std::flush
              << CryptoTools::validateDataHash(BCRYPT_HASH, valid_data, hash) << std::endl;

    std::cout << "checking wrong password: " << std::flush
              << CryptoTools::validateDataHash(BCRYPT_HASH, invalid_data, hash) << std::endl<< std::endl;
}

int main(){

    cryptotool_test();
    return 0;
}
