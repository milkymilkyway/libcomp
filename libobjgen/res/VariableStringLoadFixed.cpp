// Load a string with a fixed size buffer.
([&]() -> bool
{
    char szValue[@FIXED_LENGTH@];
    szValue[sizeof(szValue) - 1] = 0;

    @STREAM@.stream.read(szValue, sizeof(szValue) - 1);

    if(!@STREAM@.stream.good())
    {
        return false;
    }

    @SET_CODE@

    return @STREAM@.stream.good();
})()