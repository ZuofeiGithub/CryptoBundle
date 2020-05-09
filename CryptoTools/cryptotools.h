#ifndef CRYPTOTOOLS_H
#define CRYPTOTOOLS_H

#include "bcrypt/BCrypt.hpp"
#include "bytearray.h"
#include <map>
#include <any>

//AnyMap is similiar to the Qt QVariantMap data type
typedef std::map<std::string,std::any> AnyMap;

enum HashingMethod{BCRYPT=1,SHA256};

class CryptoTools
{
public:
    CryptoTools();

    ByteArray generateHash(HashingMethod method, ByteArray data, AnyMap params=AnyMap());
    /**
     * @brief validateData
     * @param data : data to be validated using given hash
     * @param hash : stored ground truth data hash
     * @return
     */
    bool validateDataHash(HashingMethod method, ByteArray data, ByteArray hash, AnyMap params=AnyMap());
};

#endif // CRYPTOTOOLS_H
