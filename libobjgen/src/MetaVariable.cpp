/**
 * @file libobjgen/src/MetaVariable.cpp
 * @ingroup libobjgen
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Meta data for an object member variable.
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

// libobjgen Includes
#include "Generator.h"
#include "MetaVariable.h"
#include "MetaObject.h"

// Standard C++11 Includes
#include <sstream>

using namespace libobjgen;

MetaVariable::MetaVariable() : mCaps(false)
{
}

std::string MetaVariable::GetName() const
{
    return mName;
}

void MetaVariable::SetName(const std::string& name)
{
    mName = name;
}

std::string MetaVariable::GetError() const
{
    return mError;
}

bool MetaVariable::IsCaps() const
{
    return mCaps;
}

void MetaVariable::SetCaps(bool caps)
{
    mCaps = caps;
}

bool MetaVariable::IsValid(const std::vector<char>& data) const
{
    return IsValid(&data[0], data.size());
}

std::string MetaVariable::GetDeclaration(const std::string& name) const
{
    std::string decl;

    if(MetaObject::IsValidIdentifier(name))
    {
        std::stringstream ss;

        ss << GetCodeType() << " " << name << ";";

        decl = ss.str();
    }

    return decl;
}

std::string MetaVariable::GetArgument(const std::string& name) const
{
    std::string arg;

    if(MetaObject::IsValidIdentifier(name))
    {
        std::stringstream ss;

        ss << "const " << GetCodeType() << "& " << name;

        arg = ss.str();
    }

    return arg;
}

std::string MetaVariable::GetGetterCode(const Generator& generator,
    const std::string& name, size_t tabLevel) const
{
    std::stringstream ss;
    ss << generator.Tab(tabLevel) << "return " << name << ";" << std::endl;

    return ss.str();
}

std::string MetaVariable::GetSetterCode(const Generator& generator,
    const std::string& name, const std::string argument, size_t tabLevel) const
{
    std::string condition = GetValidCondition(argument);

    std::stringstream ss;

    if(condition.empty())
    {
        ss << generator.Tab(tabLevel) << name << " = "
            << argument << ";" << std::endl;
        ss << std::endl;
        ss << generator.Tab(tabLevel) << "return true;" << std::endl;
    }
    else
    {
        ss << generator.Tab(tabLevel) << "if(" << condition << ")" << std::endl;
        ss << generator.Tab(tabLevel) << "{" << std::endl;
        ss << generator.Tab(tabLevel + 1) << name << " = "
            << argument << ";" << std::endl;
        ss << std::endl;
        ss << generator.Tab(tabLevel + 1) << "return true;" << std::endl;
        ss << generator.Tab(tabLevel) << "}" << std::endl;
        ss << std::endl;
        ss << generator.Tab(tabLevel) << "return false;" << std::endl;
    }

    return ss.str();
}

std::string MetaVariable::GetAccessDeclarations(const Generator& generator,
    const MetaObject& object, const std::string& name, size_t tabLevel) const
{
    std::stringstream ss;
    ss << generator.Tab(tabLevel) << GetCodeType() << " Get"
        << generator.GetCapitalName(*this) << "() const;" << std::endl;
    ss << generator.Tab(tabLevel) << "bool Set"
        << generator.GetCapitalName(*this) << "("
        << GetArgument(name) << ");" << std::endl;

    return ss.str();
}

std::string MetaVariable::GetAccessFunctions(const Generator& generator,
    const MetaObject& object, const std::string& name) const
{
    std::stringstream ss;

    ss << GetCodeType() << " " << object.GetName() << "::" << "Get"
        << generator.GetCapitalName(*this) << "() const" << std::endl;
    ss << "{" << std::endl;
    ss << GetGetterCode(generator, name);
    ss << "}" << std::endl;
    ss << std::endl;

    ss << "bool " << object.GetName() << "::" << "Set"
        << generator.GetCapitalName(*this) << "(" << GetArgument(GetName())
        << ")" << std::endl;
    ss << "{" << std::endl;
    ss << GetSetterCode(generator, name, GetName());
    ss << "}" << std::endl;

    return ss.str();
}

std::string MetaVariable::GetConstructorCode(const Generator& generator,
    const MetaObject& object, const std::string& name, size_t tabLevel) const
{
    std::string code = GetConstructValue();

    if(code.empty())
    {
        std::stringstream ss;
        ss << generator.Tab(tabLevel) << name << " = " << GetCodeType()
            << "{};" << std::endl;

        code = ss.str();
    }
    else
    {
        std::stringstream ss;
        ss << generator.Tab(tabLevel) << name << " = " << code
            << ";" << std::endl;

        code = ss.str();
    }

    return code;
}

std::string MetaVariable::GetDestructorCode(const Generator& generator,
    const MetaObject& object, const std::string& name, size_t tabLevel) const
{
    return std::string();
}

bool MetaVariable::BaseLoad(const tinyxml2::XMLElement& element)
{
    const char *szCaps = element.Attribute("caps");

    if(nullptr != szCaps)
    {
        std::string caps(szCaps);

        std::transform(caps.begin(), caps.end(), caps.begin(), ::tolower);

        SetCaps("1" == caps || "true" == caps || "on" == caps || "yes" == caps);
    }

    return true;
}

bool MetaVariable::BaseSave(tinyxml2::XMLElement& element) const
{
    if(IsCaps())
    {
        element.SetAttribute("caps", "true");
    }

    return true;
}
