([&]() -> bool
{
    for(auto value : @VAR_NAME@)
    {
        if(!(@VAR_VALID_CODE@))
        {
            return false;
        }
    }

    return true;
})()