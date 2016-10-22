{
    tinyxml2::XMLElement *pMember = doc.NewElement("member");
    pMember->SetAttribute("name", @VAR_NAME@);

    tinyxml2::XMLText *pText = doc.NewText(libcomp::String(
        "%1").Arg(@VAR_GETTER@).C());
    pMember->InsertEndChild(pText);

    @ROOT@.InsertEndChild(pMember);
}