// Load a string with a size specified.
([&]() -> bool
{
    @LENGTH_TYPE@ len;
    @STREAM@.stream.read(reinterpret_cast<char*>(&len),
        sizeof(len));

    if(!@STREAM@.stream.good())
    {
        return false;
    }

    if(0 == len)
    {
        return true;
    }

    char *szValue = new char[len + 1];
    szValue[len] = 0;

    @STREAM@.stream.read(szValue, len);

    if(!@STREAM@.stream.good())
    {
        delete[] szValue;
        return false;
    }

    @SET_CODE@

    delete[] szValue;

    return @STREAM@.stream.good();
})()