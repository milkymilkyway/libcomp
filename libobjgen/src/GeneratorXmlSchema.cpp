/**
 * @file libobjgen/src/GeneratorXmlSchema.cpp
 * @ingroup libobjgen
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief XSD generator to write the XML schema for an object.
 *
 * This file is part of the COMP_hack Object Generator Library (libobjgen).
 *
 * Copyright (C) 2012-2020 COMP_hack Team <compomega@tutanota.com>
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

#include "GeneratorXmlSchema.h"

// libobjgen Includes
#include "MetaObject.h"
#include "MetaObjectXmlParser.h"
#include "MetaVariable.h"
#include "MetaVariableEnum.h"
#include "MetaVariableMap.h"
#include "MetaVariableReference.h"

// Standard C++11 Includes
#include <algorithm>
#include <limits>
#include <sstream>

using namespace libobjgen;

std::string GeneratorXmlSchema::Generate(const MetaObject &obj) {
  (void)obj;

  mDoc.InsertEndChild(mDoc.NewDeclaration());
  mDoc.InsertEndChild(mDoc.NewComment(" THIS FILE IS GENERATED "));
  mDoc.InsertEndChild(mDoc.NewComment(" DO NOT MODIFY THE CONTENTS "));
  mDoc.InsertEndChild(mDoc.NewComment(" DO NOT COMMIT TO VERSION CONTROL "));
  mRoot =
      (tinyxml2::XMLElement *)mDoc.InsertEndChild(mDoc.NewElement("xs:schema"));
  mRoot->SetAttribute("xmlns:xs", "http://www.w3.org/2001/XMLSchema");

  GenerateBasicTypes();

  std::set<std::string> references;
  GetReferences(mKnownObjects.find(obj.GetName())->second, references);

  for (auto refType : references) {
    auto refObject = mKnownObjects.find(refType)->second;

    auto pSequence = GenerateObjectType(refType);

    for (auto it = refObject->VariablesBegin(); it != refObject->VariablesEnd();
         ++it) {
      auto var = *it;

      var->GenerateSchemaType(this, refType);
      var->GenerateSchema(this, pSequence, refType);
    }
  }

  {
    auto pObjects = mDoc.NewElement("xs:element");
    pObjects->SetAttribute("name", "objects");
    auto pComplexType = mDoc.NewElement("xs:complexType");
    auto pSequence = mDoc.NewElement("xs:sequence");
    auto pElement = mDoc.NewElement("xs:element");
    pElement->SetAttribute("name", "object");
    pElement->SetAttribute("maxOccurs", "unbounded");
    pElement->SetAttribute("type", obj.GetName().c_str());
    pObjects->InsertEndChild(pComplexType);
    pComplexType->InsertEndChild(pSequence);
    pSequence->InsertEndChild(pElement);
    mRoot->InsertEndChild(pObjects);
  }

  std::stringstream ss;
  tinyxml2::XMLPrinter printer;
  mDoc.Print(&printer);

  ss << printer.CStr();

  return ss.str();
}

void GeneratorXmlSchema::GenerateBasicTypes() {
  GenerateIntegerType(
      "s8", std::to_string(std::numeric_limits<int8_t>::min()).c_str(),
      std::to_string(std::numeric_limits<int8_t>::max()).c_str());
  GenerateIntegerType(
      "u8", std::to_string(std::numeric_limits<uint8_t>::min()).c_str(),
      std::to_string(std::numeric_limits<uint8_t>::max()).c_str());
  GenerateIntegerType(
      "s16", std::to_string(std::numeric_limits<int16_t>::min()).c_str(),
      std::to_string(std::numeric_limits<int16_t>::max()).c_str());
  GenerateIntegerType(
      "u16", std::to_string(std::numeric_limits<uint16_t>::min()).c_str(),
      std::to_string(std::numeric_limits<uint16_t>::max()).c_str());
  GenerateIntegerType(
      "s32", std::to_string(std::numeric_limits<int32_t>::min()).c_str(),
      std::to_string(std::numeric_limits<int32_t>::max()).c_str());
  GenerateIntegerType(
      "u32", std::to_string(std::numeric_limits<uint32_t>::min()).c_str(),
      std::to_string(std::numeric_limits<uint32_t>::max()).c_str());
  GenerateIntegerType(
      "s64", std::to_string(std::numeric_limits<int64_t>::min()).c_str(),
      std::to_string(std::numeric_limits<int64_t>::max()).c_str());
  GenerateIntegerType(
      "u64", std::to_string(std::numeric_limits<uint64_t>::min()).c_str(),
      std::to_string(std::numeric_limits<uint64_t>::max()).c_str());
  GenerateEnumType("bool", {"true", "false"});
}

void GeneratorXmlSchema::GenerateIntegerType(const std::string &szName,
                                             const std::string &szMin,
                                             const std::string &szMax) {
  auto pSimpleType = mDoc.NewElement("xs:simpleType");
  pSimpleType->SetAttribute("name", szName.c_str());

  auto pRestriction = mDoc.NewElement("xs:restriction");
  pRestriction->SetAttribute("base", "xs:integer");

  auto pMinInclusive = mDoc.NewElement("xs:minInclusive");
  pMinInclusive->SetAttribute("value", szMin.c_str());

  auto pMaxInclusive = mDoc.NewElement("xs:maxInclusive");
  pMaxInclusive->SetAttribute("value", szMax.c_str());

  pSimpleType->InsertEndChild(pRestriction);
  pRestriction->InsertEndChild(pMinInclusive);
  pRestriction->InsertEndChild(pMaxInclusive);
  mRoot->InsertEndChild(pSimpleType);
}

void GeneratorXmlSchema::GenerateStringType(const std::string &szName,
                                            size_t maxLength) {
  auto pSimpleType = mDoc.NewElement("xs:simpleType");
  pSimpleType->SetAttribute("name", szName.c_str());

  auto pRestriction = mDoc.NewElement("xs:restriction");
  pRestriction->SetAttribute("base", "xs:string");

  auto pMaxLength = mDoc.NewElement("xs:maxLength");
  pMaxLength->SetAttribute("value", std::to_string(maxLength).c_str());

  pSimpleType->InsertEndChild(pRestriction);
  pRestriction->InsertEndChild(pMaxLength);
  mRoot->InsertEndChild(pSimpleType);
}

void GeneratorXmlSchema::GenerateEnumType(
    const std::string &szName, const std::list<std::string> &enumValues) {
  auto pSimpleType = mDoc.NewElement("xs:simpleType");
  pSimpleType->SetAttribute("name", szName.c_str());

  auto pRestriction = mDoc.NewElement("xs:restriction");
  pRestriction->SetAttribute("base", "xs:string");

  for (auto enumValue : enumValues) {
    auto pEnumeration = mDoc.NewElement("xs:enumeration");
    pEnumeration->SetAttribute("value", enumValue.c_str());
    pRestriction->InsertEndChild(pEnumeration);
  }

  pSimpleType->InsertEndChild(pRestriction);
  mRoot->InsertEndChild(pSimpleType);
}

tinyxml2::XMLElement *GeneratorXmlSchema::GenerateObjectType(
    const std::string &szName) {
  auto pComplexType = mDoc.NewElement("xs:complexType");
  pComplexType->SetAttribute("name", szName.c_str());

  auto pSequence = mDoc.NewElement("xs:sequence");

  auto pNameAttribute = mDoc.NewElement("xs:attribute");
  pNameAttribute->SetAttribute("name", "name");
  pNameAttribute->SetAttribute("type", "xs:string");
  pNameAttribute->SetAttribute("fixed", szName.c_str());
  pNameAttribute->SetAttribute("use", "required");

  pComplexType->InsertEndChild(pSequence);
  pComplexType->InsertEndChild(pNameAttribute);
  mRoot->InsertEndChild(pComplexType);

  return pSequence;
}

void GeneratorXmlSchema::GenerateMemberType(tinyxml2::XMLElement *pSequence,
                                            const std::string &szName,
                                            const std::string &szType,
                                            bool isObject) {
  auto pElement = mDoc.NewElement("xs:element");
  pElement->SetAttribute("name", "member");

  auto pComplexType = mDoc.NewElement("xs:complexType");

  auto pNameAttribute = mDoc.NewElement("xs:attribute");
  pNameAttribute->SetAttribute("name", "name");
  pNameAttribute->SetAttribute("type", "xs:string");
  pNameAttribute->SetAttribute("fixed", szName.c_str());
  pNameAttribute->SetAttribute("use", "required");

  if (isObject) {
    auto pSubElement = mDoc.NewElement("xs:element");
    pSubElement->SetAttribute("name", "object");
    pSubElement->SetAttribute("type", szType.c_str());

    auto pSubSequence = mDoc.NewElement("xs:sequence");

    pSubSequence->InsertEndChild(pSubElement);
    pComplexType->InsertEndChild(pSubSequence);
    pComplexType->InsertEndChild(pNameAttribute);
  } else {
    auto pSimpleContent = mDoc.NewElement("xs:simpleContent");

    auto pExtension = mDoc.NewElement("xs:extension");
    pExtension->SetAttribute("base", szType.c_str());

    pComplexType->InsertEndChild(pSimpleContent);
    pSimpleContent->InsertEndChild(pExtension);
    pExtension->InsertEndChild(pNameAttribute);
  }

  pElement->InsertEndChild(pComplexType);

  auto pLastMember = pSequence->LastChildElement("xs:element");

  if (pLastMember) {
    pSequence->InsertAfterChild(pLastMember, pElement);
    pSequence->InsertAfterChild(pLastMember,
                                mDoc.NewComment((" " + szName + " ").c_str()));
  } else {
    pSequence->InsertFirstChild(pElement);
    pSequence->InsertFirstChild(mDoc.NewComment((" " + szName + " ").c_str()));
  }
}

void GeneratorXmlSchema::GenerateMemberArrayType(
    tinyxml2::XMLElement *pSequence, const std::string &szName,
    const std::string &szType, size_t size, bool isObject) {
  auto pElement = mDoc.NewElement("xs:element");
  pElement->SetAttribute("name", "member");

  auto pComplexType = mDoc.NewElement("xs:complexType");
  auto pSubSequence = mDoc.NewElement("xs:sequence");

  auto pSubElement = mDoc.NewElement("xs:element");
  pSubElement->SetAttribute("name", "element");

  if (size) {
    pSubElement->SetAttribute("minOccurs", std::to_string(size).c_str());
    pSubElement->SetAttribute("maxOccurs", std::to_string(size).c_str());
  } else {
    pSubElement->SetAttribute("minOccurs", "0");
    pSubElement->SetAttribute("maxOccurs", "unbounded");
  }

  auto pNameAttribute = mDoc.NewElement("xs:attribute");
  pNameAttribute->SetAttribute("name", "name");
  pNameAttribute->SetAttribute("type", "xs:string");
  pNameAttribute->SetAttribute("fixed", szName.c_str());
  pNameAttribute->SetAttribute("use", "required");

  pElement->InsertEndChild(pComplexType);
  pComplexType->InsertEndChild(pSubSequence);
  pComplexType->InsertEndChild(pNameAttribute);
  pSubSequence->InsertEndChild(pSubElement);

  if (isObject) {
    auto pSubComplexType = mDoc.NewElement("xs:complexType");
    auto pSubSubSequence = mDoc.NewElement("xs:sequence");

    auto pSubSubElement = mDoc.NewElement("xs:element");
    pSubSubElement->SetAttribute("name", "object");
    pSubSubElement->SetAttribute("type", szType.c_str());

    pSubElement->InsertEndChild(pSubComplexType);
    pSubComplexType->InsertEndChild(pSubSubSequence);
    pSubSubSequence->InsertEndChild(pSubSubElement);
  } else {
    pSubElement->SetAttribute("type", szType.c_str());
  }

  auto pLastMember = pSequence->LastChildElement("xs:element");

  if (pLastMember) {
    pSequence->InsertAfterChild(pLastMember, pElement);
    pSequence->InsertAfterChild(pLastMember,
                                mDoc.NewComment((" " + szName + " ").c_str()));
  } else {
    pSequence->InsertFirstChild(pElement);
    pSequence->InsertFirstChild(mDoc.NewComment((" " + szName + " ").c_str()));
  }
}

void GeneratorXmlSchema::GenerateMemberMapType(tinyxml2::XMLElement *pSequence,
                                               const std::string &szName,
                                               const std::string &szKeyType,
                                               const std::string &szValueType,
                                               bool isObject) {
  auto pElement = mDoc.NewElement("xs:element");
  pElement->SetAttribute("name", "member");

  auto pComplexType = mDoc.NewElement("xs:complexType");
  auto pSubSequence = mDoc.NewElement("xs:sequence");

  auto pPairElement = mDoc.NewElement("xs:element");
  pPairElement->SetAttribute("name", "pair");
  pPairElement->SetAttribute("minOccurs", "0");
  pPairElement->SetAttribute("maxOccurs", "unbounded");

  auto pKeyElement = mDoc.NewElement("xs:element");
  pKeyElement->SetAttribute("name", "key");
  pKeyElement->SetAttribute("type", szKeyType.c_str());

  auto pValueElement = mDoc.NewElement("xs:element");
  pValueElement->SetAttribute("name", "value");

  auto pPairComplexType = mDoc.NewElement("xs:complexType");
  auto pPairSequence = mDoc.NewElement("xs:sequence");

  pPairSequence->InsertEndChild(pKeyElement);
  pPairSequence->InsertEndChild(pValueElement);
  pPairComplexType->InsertEndChild(pPairSequence);

  auto pNameAttribute = mDoc.NewElement("xs:attribute");
  pNameAttribute->SetAttribute("name", "name");
  pNameAttribute->SetAttribute("type", "xs:string");
  pNameAttribute->SetAttribute("fixed", szName.c_str());
  pNameAttribute->SetAttribute("use", "required");

  pPairSequence->InsertEndChild(pKeyElement);
  pPairSequence->InsertEndChild(pValueElement);
  pPairComplexType->InsertEndChild(pPairSequence);
  pPairElement->InsertEndChild(pPairComplexType);
  pElement->InsertEndChild(pComplexType);
  pComplexType->InsertEndChild(pSubSequence);
  pComplexType->InsertEndChild(pNameAttribute);
  pSubSequence->InsertEndChild(pPairElement);

  if (isObject) {
    auto pSubComplexType = mDoc.NewElement("xs:complexType");
    auto pSubSubSequence = mDoc.NewElement("xs:sequence");

    auto pSubSubElement = mDoc.NewElement("xs:element");
    pSubSubElement->SetAttribute("name", "object");
    pSubSubElement->SetAttribute("type", szValueType.c_str());

    pValueElement->InsertEndChild(pSubComplexType);
    pSubComplexType->InsertEndChild(pSubSubSequence);
    pSubSubSequence->InsertEndChild(pSubSubElement);
  } else {
    pValueElement->SetAttribute("type", szValueType.c_str());
  }

  auto pLastMember = pSequence->LastChildElement("xs:element");

  if (pLastMember) {
    pSequence->InsertAfterChild(pLastMember, pElement);
    pSequence->InsertAfterChild(pLastMember,
                                mDoc.NewComment((" " + szName + " ").c_str()));
  } else {
    pSequence->InsertFirstChild(pElement);
    pSequence->InsertFirstChild(mDoc.NewComment((" " + szName + " ").c_str()));
  }
}

void GeneratorXmlSchema::SetXmlParser(MetaObjectXmlParser *pParser) {
  mKnownObjects = pParser->GetKnownObjects();
}

void GeneratorXmlSchema::GetReferences(
    const std::shared_ptr<MetaObject> obj,
    std::set<std::string> &references) const {
  references.insert(obj->GetName());

  for (auto var : obj->GetReferences()) {
    std::shared_ptr<MetaVariableReference> ref =
        std::dynamic_pointer_cast<MetaVariableReference>(var);

    if (ref->IsGeneric()) {
      continue;
    }

    auto refType = ref->GetReferenceType();
    auto refObject = mKnownObjects.find(refType);

    if (refObject != mKnownObjects.end()) {
      GetReferences(refObject->second, references);
    }
  }
}
