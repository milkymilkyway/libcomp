/**
 * @file libobjgen/src/GeneratorXmlSchema.h
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

#ifndef LIBOBJGEN_SRC_GENERATORXMLSCHEMA_H
#define LIBOBJGEN_SRC_GENERATORXMLSCHEMA_H

// libobjgen Includes
#include "Generator.h"

// Standard C++ Includes
#include <set>
#include <unordered_map>

// Ignore warnings
#include "PushIgnore.h"

// tinyxml2 Includes
#include <tinyxml2.h>

// Stop ignoring warnings
#include "PopIgnore.h"

namespace libobjgen {

class GeneratorXmlSchema : public Generator {
 public:
  virtual std::string Generate(const MetaObject &obj);

  void GenerateIntegerType(const std::string &szName, const std::string &szMin,
                           const std::string &szMax);
  void GenerateStringType(const std::string &szName, size_t maxLength);
  void GenerateEnumType(const std::string &szName,
                        const std::list<std::string> &enumValues);
  tinyxml2::XMLElement *GenerateObjectType(const std::string &szName);
  void GenerateMemberType(tinyxml2::XMLElement *pSequence,
                          const std::string &szName, const std::string &szType,
                          bool isObject = false);
  void GenerateMemberArrayType(tinyxml2::XMLElement *pSequence,
                               const std::string &szName,
                               const std::string &szType, size_t size,
                               bool isObject = false);
  void GenerateMemberMapType(tinyxml2::XMLElement *pSequence,
                             const std::string &szName,
                             const std::string &szKeyType,
                             const std::string &szValueType,
                             bool isObject = false);

  void SetXmlParser(MetaObjectXmlParser *pParser) override;

 private:
  void GenerateBasicTypes();

  void GetReferences(const std::shared_ptr<MetaObject> obj,
                     std::set<std::string> &references) const;

  tinyxml2::XMLDocument mDoc;
  tinyxml2::XMLElement *mRoot;

  std::unordered_map<std::string, std::shared_ptr<MetaObject>> mKnownObjects;
};

}  // namespace libobjgen

#endif  // LIBOBJGEN_SRC_GENERATORXMLSCHEMA_H
