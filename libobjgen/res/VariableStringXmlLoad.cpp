([&]() -> libcomp::String
{
    auto s = libcomp::String(GetXmlText(*@NODE@)).Replace("&#10;", "\r");

#if @FIXED_LENGTH@
    if(@FIXED_LENGTH@ && @FIXED_LENGTH@ <= @ENCODED_SIZE@)
    {
        LogGeneralError([&]()
        {
            return libcomp::String("String is too long and may not load: %1\n").Arg(s);
        });

        LogGeneralError([&]()
        {
            return libcomp::String("String is %1 bytes when encoded but has to be under %2 bytes.\n").Arg(@ENCODED_SIZE@).Arg(@FIXED_LENGTH@);
        });
    }
#endif

    return s;
})()
