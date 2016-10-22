// Save a string with a fixed size buffer.
([&]() -> bool
{
    static const char zero[@FIXED_LENGTH@] = { 0 };

    @ENCODE_CODE@

    if(@STREAM@.stream.good() && @FIXED_LENGTH@ != value.size())
    {
        @STREAM@.stream.write(zero, static_cast<std::streamsize>(
            @FIXED_LENGTH@) - static_cast<std::streamsize>(value.size()));
    }

    return @STREAM@.stream.good();
})()