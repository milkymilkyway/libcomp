[&]()
{
    libobjgen::UUID uuid;

    if(@VAR_NAME@)
    {
        uuid = @VAR_NAME@->GetUUID();
    }

    std::vector<char> data = uuid.ToData();

    return @STREAM@.write(&data[0], data.size()).good();
}