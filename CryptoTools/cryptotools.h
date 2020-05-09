#ifndef CRYPTOTOOLS_H
#define CRYPTOTOOLS_H

#include "bcrypt/inc/BCrypt.hpp"
#include "bytearray.h"
#include <map>
#include <any>

//AnyMap is similiar to the Qt QVariantMap data type
typedef std::map<std::string,std::any> AnyMap;

enum HashingMethod{BCRYPT_HASH=1,SHA256_HASH};

class CryptoTools
{
public:
    CryptoTools();

    /**
     * @brief generateHash using the specified method, optional method parameter list is given via AnyMap
     * @param method
     * @param data
     * @param params
     * @return
     */
    static ByteArray generateHash(HashingMethod method, ByteArray data, AnyMap params=AnyMap());
    /**
     * @brief validateData
     * @param data : data to be validated using given hash
     * @param hash : stored ground truth data hash
     * @return
     */
    static bool validateDataHash(HashingMethod method, ByteArray data, ByteArray hash, AnyMap params=AnyMap());
};

#endif // CRYPTOTOOLS_H
