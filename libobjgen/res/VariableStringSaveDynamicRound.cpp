// Save a string with a size specified.
([&]() -> bool
{
    std::stringstream @ENCODESTREAM@;

    @ENCODE_CODE@

    if(@STREAM@.good())
    {
        @LENGTH_TYPE@ len = static_cast<@LENGTH_TYPE@>(value.size());
        @LENGTH_TYPE@ rounded = (0 == len) ? @ROUND@ :
            ((len + @ROUND@ - 1) / @ROUND@) * @ROUND@;
        @STREAM@.write(reinterpret_cast<const char*>(&rounded),
            sizeof(rounded));
        @LENGTH_TYPE@ left = rounded - len;

        static const char zero[4] = { 0, 0, 0, 0 };

        if(@STREAM@.good() && len > 0)
        {
            @STREAM@ << @ENCODESTREAM@.rdbuf();

            if(0 < left)
            {
                @STREAM@.write(zero, left);
            }
        }
        else if(@STREAM@.good())
        {
            @STREAM@.write(zero, @ROUND@);
        }
    }

    return @STREAM@.good();
})()
