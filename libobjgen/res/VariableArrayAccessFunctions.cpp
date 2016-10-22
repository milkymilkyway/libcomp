@VAR_TYPE@ @OBJECT_NAME@::Get@VAR_CAMELCASE_NAME@(size_t index) const
{
    if(@ELEMENT_COUNT@ <= index)
    {
        return @VAR_TYPE@{};
    }

    @VAR_GETTER_CODE@
}

bool @OBJECT_NAME@::Set@VAR_CAMELCASE_NAME@(size_t index, @VAR_ARGUMENT@)
{
    if(@ELEMENT_COUNT@ <= index)
    {
        return false;
    }

    @VAR_SETTER_CODE@
}