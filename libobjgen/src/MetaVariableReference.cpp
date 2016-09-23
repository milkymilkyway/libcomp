/**
 * @file libobjgen/src/MetaVariableReference.cpp
 * @ingroup libobjgen
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Meta data for a member variable that is a reference to another object.
 *
 * This file is part of the COMP_hack Object Generator Library (libobjgen).
 *
 * Copyright (C) 2012-2016 COMP_hack Team <compomega@tutanota.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "MetaVariableReference.h"

// libobjgen Includes
#include "Generator.h"
#include "MetaObject.h"

// Standard C++11 Libraries
#include <sstream>

using namespace libobjgen;

MetaVariableReference::MetaVariableReference() : MetaVariable()
{
}

MetaVariableReference::~MetaVariableReference()
{
}

size_t MetaVariableReference::GetSize() const
{
    return 16u; // Size of a UUID.
}

std::string MetaVariableReference::GetType() const
{
    return mReferenceType + "*";
}

std::string MetaVariableReference::GetReferenceType() const
{
    return mReferenceType;
}

bool MetaVariableReference::SetReferenceType(const std::string& referenceType)
{
    bool status = false;

    if(MetaObject::IsValidIdentifier(referenceType))
    {
        status = true;
        mReferenceType = referenceType;
    }

    return status;
}

bool MetaVariableReference::IsCoreType() const
{
    return false;
}

bool MetaVariableReference::IsValid() const
{
    /// @todo Fix
    return MetaObject::IsValidIdentifier(mReferenceType) &&
        MetaObject::IsValidIdentifier(GetName());
}

bool MetaVariableReference::IsValid(const void *pData, size_t dataSize) const
{
    (void)pData;
    (void)dataSize;

    /// @todo Fix
    return true;
}

bool MetaVariableReference::Load(std::istream& stream)
{
    (void)stream;

    /// @todo Fix
    return true;
}

bool MetaVariableReference::Save(std::ostream& stream) const
{
    (void)stream;

    /// @todo Fix
    return true;
}

bool MetaVariableReference::Load(const tinyxml2::XMLDocument& doc,
    const tinyxml2::XMLElement& root)
{
    (void)doc;

    /// @todo Fix
    return BaseLoad(root);
}

bool MetaVariableReference::Save(tinyxml2::XMLDocument& doc,
    tinyxml2::XMLElement& root) const
{
    (void)doc;

    /// @todo Fix
    return BaseSave(root);
}

std::string MetaVariableReference::GetCodeType() const
{
    std::string code;

    if(!mReferenceType.empty())
    {
        std::stringstream ss;
        ss << "std::shared_ptr<" << mReferenceType << ">";

        code = ss.str();
    }

    return code;
}

std::string MetaVariableReference::GetConstructValue() const
{
    std::stringstream ss;
    ss << GetCodeType() << "(new " << GetReferenceType() << ")";

    return ss.str();
}

std::string MetaVariableReference::GetValidCondition(
    const std::string& name, bool recursive) const
{
    std::stringstream ss;

    if(recursive)
    {
        ss << name  << " && (!recursive || " << name
            << "->IsValid(recursive))";
    }
    else
    {
        ss << name;
    }

    return ss.str();
}

std::string MetaVariableReference::GetLoadCode(const std::string& name,
    const std::string& stream) const
{
    std::stringstream ss;
    ss << name << " && " << name << "->Load(" << stream << ")";

    return ss.str();
}

std::string MetaVariableReference::GetSaveCode(const std::string& name,
    const std::string& stream) const
{
    std::stringstream ss;
    ss << name << " && " << name << "->Save(" << stream << ")";

    return ss.str();
}

std::string MetaVariableReference::GetXmlLoadCode(const Generator& generator,
    const std::string& name, const std::string& doc,
    const std::string& root, const std::string& members,
    size_t tabLevel) const
{
    (void)members;

    std::stringstream ss;
    ss << generator.Tab(tabLevel) << "if(" << name << ")" << std::endl;
    ss << generator.Tab(tabLevel) << "{" << std::endl;
    ss << generator.Tab(tabLevel + 1) << "status = " << name << "->Load("
        << doc << ", " << root << ");" << std::endl;
    ss << generator.Tab(tabLevel) << "}" << std::endl;

    return ss.str();
}

std::string MetaVariableReference::GetXmlSaveCode(const Generator& generator,
    const std::string& name, const std::string& doc,
    const std::string& root, size_t tabLevel) const
{
    std::stringstream ss;
    ss << generator.Tab(tabLevel) << "if(" << name << ")" << std::endl;
    ss << generator.Tab(tabLevel) << "{" << std::endl;
    ss << generator.Tab(tabLevel + 1) << "status = " << name << "->Save("
        << doc << ", " << root << ");" << std::endl;
    ss << generator.Tab(tabLevel) << "}" << std::endl;

    return ss.str();
}
