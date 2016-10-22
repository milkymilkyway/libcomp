{
    tinyxml2::XMLText *pText = @DOC@.NewText(@GETTER@.C());
    pText->SetCData(true);

    tinyxml2::XMLElement *pMember = @DOC@.NewElement("member");
    pMember->SetAttribute("name", @VAR_NAME@);
    pMember->InsertEndChild(pText);

    @ROOT@.InsertEndChild(pMember);
}