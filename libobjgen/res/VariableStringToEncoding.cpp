std::vector<char> value = libcomp::Convert::ToEncoding(
    @ENCODING@, @VAR_NAME@);

if(!value.empty())
{
    @STREAM@.stream.write(&value[0], static_cast<std::streamsize>(
        value.size()));
}