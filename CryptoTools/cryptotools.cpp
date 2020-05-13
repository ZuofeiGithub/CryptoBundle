#include "cryptotools.h"

CryptoTools::CryptoTools()
{

}

ByteArray CryptoTools::generateHash(HashingMethod method,const ByteArray data, AnyMap params)
{
    if(method==BCRYPT_HASH)
    {
        assert(data.getSize()<=MAXIMUM_DATA_LENGTH);
        int workload = 12;
        if(params.size()>0)
        {
            //if contains this key
            if(params.find( "workload" ) != params.end())
            {
                workload = std::any_cast<int>(params["workload"]);
            }
        }

        return BCrypt::generateHash(data,workload);
    }
    return ByteArray{};
}


bool CryptoTools::validateDataHash(HashingMethod method, const ByteArray data,const ByteArray hash, AnyMap params)
{
    if(params.size()>0)
    {
        //extract params
    }

    if(method==BCRYPT_HASH)
    {
        assert(data.getSize()<=MAXIMUM_DATA_LENGTH);
        return BCrypt::validatePassword(data, hash);
    }
    return false;
}
