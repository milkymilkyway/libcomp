/**
 * @file libobjgen/src/MetaVariableArray.cpp
 * @ingroup libobjgen
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Meta data for a member variable that is an array of variables.
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

#include "MetaVariableArray.h"

// libobjgen Includes
#include "Generator.h"
#include "MetaObject.h"

// Standard C++11 Libraries
#include <sstream>

using namespace libobjgen;

MetaVariableArray::MetaVariableArray(
    const std::shared_ptr<MetaVariable>& elementType) : MetaVariable(),
    mElementCount(0), mElementType(elementType)
{
}

MetaVariableArray::~MetaVariableArray()
{
}

size_t MetaVariableArray::GetSize() const
{
    if(mElementType)
    {
        return mElementType->GetSize() * mElementCount;
    }
    else
    {
        return 0;
    }
}

std::shared_ptr<MetaVariable> MetaVariableArray::GetElementType() const
{
    return mElementType;
}

size_t MetaVariableArray::GetElementCount() const
{
    return mElementCount;
}

void MetaVariableArray::SetElementCount(size_t elementCount)
{
    mElementCount = elementCount;
}

std::string MetaVariableArray::GetType() const
{
    return "array";
}

bool MetaVariableArray::IsCoreType() const
{
    return false;
}

bool MetaVariableArray::IsValid() const
{
    return 0 != mElementCount && MetaObject::IsValidIdentifier(GetName()) &&
        mElementType && mElementType->IsValid();
}

bool MetaVariableArray::IsValid(const void *pData, size_t dataSize) const
{
    (void)pData;
    (void)dataSize;

    /// @todo Fix
    return true;
}

bool MetaVariableArray::Load(std::istream& stream)
{
    (void)stream;

    /// @todo Fix
    return true;
}

bool MetaVariableArray::Save(std::ostream& stream) const
{
    (void)stream;

    /// @todo Fix
    return true;
}

bool MetaVariableArray::Load(const tinyxml2::XMLDocument& doc,
    const tinyxml2::XMLElement& root)
{
    (void)doc;

    bool status = true;

    const char *szSize = root.Attribute("size");

    if(nullptr != szSize)
    {
        std::stringstream ss(szSize);

        size_t elementCount = 0;
        ss >> elementCount;

        if(ss && 0 < elementCount)
        {
            SetElementCount(elementCount);
        }
        else
        {
            status = false;
        }
    }
    else
    {
        SetElementCount(0);

        status = false;
    }

    return status && BaseLoad(root) && IsValid();
}

bool MetaVariableArray::Save(tinyxml2::XMLDocument& doc,
    tinyxml2::XMLElement& root) const
{
    (void)doc;
    (void)root;

    /// @todo Fix
    return true;
}

std::string MetaVariableArray::GetCodeType() const
{
    if(mElementType)
    {
        std::stringstream ss;
        ss << "std::array<" << mElementType->GetCodeType() << ", "
            << mElementCount << ">";

        return ss.str();
    }
    else
    {
        return std::string();
    }
}

std::string MetaVariableArray::GetConstructValue() const
{
    if(mElementType)
    {
        std::string value = mElementType->GetConstructValue();

        if(!value.empty() && 0 < mElementCount)
        {
            std::stringstream ss;
            ss << "{{ " << value;

            for(size_t i = 1; i < mElementCount; ++i)
            {
                ss << ", " << value;
            }

            ss << " }}";

            value = ss.str();
        }

        return value;
    }
    else
    {
        return std::string();
    }
}

std::string MetaVariableArray::GetValidCondition(const std::string& name,
    bool recursive) const
{
    std::string code;

    if(mElementType)
    {
        code = mElementType->GetValidCondition("value", recursive);

        if(!code.empty())
        {
            std::stringstream ss;
            ss << "( [&]() -> bool { ";
            ss << "for(auto value : " << name << ") { ";
            ss << "if(!(" << code << ")) { ";
            ss << "return false; ";
            ss << "} ";
            ss << "} ";
            ss << "return true; ";
            ss << "} )()";

            code = ss.str();
        }
    }

    return code;
}

std::string MetaVariableArray::GetLoadCode(const std::string& name,
    const std::string& stream) const
{
    std::string code;

    if(mElementType && MetaObject::IsValidIdentifier(name) &&
        MetaObject::IsValidIdentifier(stream))
    {
        code = mElementType->GetLoadCode("value", stream);

        if(!code.empty())
        {
            std::stringstream ss;
            ss << "( [&]() -> bool { ";
            ss << "for(auto& value : " << name << ") { ";
            ss << "if(!(" << code << ")) { ";
            ss << "return false; ";
            ss << "} ";
            ss << "} ";
            ss << "return " << stream << ".stream.good(); ";
            ss << "} )()";

            code = ss.str();
        }
    }

    return code;
}

std::string MetaVariableArray::GetSaveCode(const std::string& name,
    const std::string& stream) const
{
    std::string code;

    if(mElementType && MetaObject::IsValidIdentifier(name) &&
        MetaObject::IsValidIdentifier(stream))
    {
        code = mElementType->GetSaveCode("value", stream);

        if(!code.empty())
        {
            std::stringstream ss;
            ss << "( [&]() -> bool { ";
            ss << "for(auto value : " << name << ") { ";
            ss << "if(!(" << code << ")) { ";
            ss << "return false; ";
            ss << "} ";
            ss << "} ";
            ss << "return " << stream << ".stream.good(); ";
            ss << "} )()";

            code = ss.str();
        }
    }

    return code;
}

std::string MetaVariableArray::GetXmlLoadCode(const Generator& generator,
    const std::string& name, const std::string& doc,
    const std::string& root, const std::string& members,
    size_t tabLevel) const
{
    (void)generator;
    (void)name;
    (void)doc;
    (void)root;
    (void)members;
    (void)tabLevel;

    /// @todo Fix
    return std::string();
}

std::string MetaVariableArray::GetXmlSaveCode(const Generator& generator,
    const std::string& name, const std::string& doc,
    const std::string& root, size_t tabLevel) const
{
    (void)generator;
    (void)name;
    (void)doc;
    (void)root;
    (void)tabLevel;

    /// @todo Fix
    return std::string();
}

std::string MetaVariableArray::GetAccessDeclarations(const Generator& generator,
    const MetaObject& object, const std::string& name, size_t tabLevel) const
{
    std::stringstream ss;
    ss << MetaVariable::GetAccessDeclarations(generator,
        object, name, tabLevel);

    if(mElementType)
    {
        ss << generator.Tab(tabLevel) << mElementType->GetCodeType() << " Get"
            << generator.GetCapitalName(*this)
            << "(size_t index) const;" << std::endl;
        ss << generator.Tab(tabLevel) << "bool Set"
            << generator.GetCapitalName(*this) << "(size_t index, "
            << mElementType->GetArgument(name) << ");" << std::endl;
    }

    return ss.str();
}

std::string MetaVariableArray::GetAccessFunctions(const Generator& generator,
    const MetaObject& object, const std::string& name) const
{
    std::stringstream ss;
    ss << MetaVariable::GetAccessFunctions(generator, object, name);

    if(mElementType)
    {
        ss << mElementType->GetCodeType() << " " << object.GetName()
            << "::" << "Get" << generator.GetCapitalName(*this)
            << "(size_t index) const" << std::endl;
        ss << "{" << std::endl;
        ss << generator.Tab(1) << "if(" << mElementCount
            << " <= index)" << std::endl;
        ss << generator.Tab(1) << "{" << std::endl;
        ss << generator.Tab(2) << "return " << mElementType->GetCodeType()
            << "{};" << std::endl;
        ss << generator.Tab(1) << "}" << std::endl;
        ss << mElementType->GetGetterCode(generator, name + "[index]");
        ss << "}" << std::endl;
        ss << std::endl;

        ss << "bool " << object.GetName() << "::" << "Set"
            << generator.GetCapitalName(*this) << "(size_t index, "
            << mElementType->GetArgument(GetName()) << ")" << std::endl;
        ss << "{" << std::endl;
        ss << generator.Tab(1) << "if(" << mElementCount
            << " <= index)" << std::endl;
        ss << generator.Tab(1) << "{" << std::endl;
        ss << generator.Tab(2) << "return false;" << std::endl;
        ss << generator.Tab(1) << "}" << std::endl;
        ss << std::endl;
        ss << mElementType->GetSetterCode(generator,
            name + "[index]", GetName());
        ss << "}" << std::endl;
    }

    return ss.str();
}
