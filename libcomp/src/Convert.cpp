/**
 * @file libcomp/src/Convert.cpp
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Routines to convert strings between encodings.
 *
 * This file is part of the COMP_hack Library (libcomp).
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

#include "Convert.h"

#include "Endian.h"
#include "EnumMap.h"
#include "Exception.h"
#include "Log.h"

// Standard C Includes
#include <stdint.h>

#include <climits>

// Lookup tables
#include "LookupTableCP1250.h"
#include "LookupTableCP1251.h"
#include "LookupTableCP1252.h"
#include "LookupTableCP1253.h"
#include "LookupTableCP1254.h"
#include "LookupTableCP1255.h"
#include "LookupTableCP1256.h"
#include "LookupTableCP1257.h"
#include "LookupTableCP1258.h"
#include "LookupTableCP1361.h"
#include "LookupTableCP874.h"
#include "LookupTableCP932.h"
#include "LookupTableCP936.h"
#include "LookupTableCP949.h"
#include "LookupTableCP950.h"

using namespace libcomp;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

/// Default encoding to use when none is specified.
static Convert::Encoding_t gDefaultEncoding =
    Convert::Encoding_t::ENCODING_CP932;

/**
 * Convert a single byte character set (SBCS) encoded string to a @ref String.
 * @param szString The string to convert.
 * @param size Optional size of the string.
 * @param pLookupTable Lookup table to use.
 * @returns The converted string.
 */
static String FromSBCSEncoding(const uint8_t *szString, int size,
                               const uint8_t *pLookupTable);

/**
 * Convert a double byte character set (DBCS) encoded string to a @ref String.
 * @param szString The string to convert.
 * @param size Optional size of the string.
 * @param pLookupTable Lookup table to use.
 * @returns The converted string.
 */
static String FromDBCSEncoding(const uint8_t *szString, int size,
                               const uint8_t *pLookupTable);

/**
 * Convert the @ref String to a single byte character set (SBCS) encoded string.
 * @param str String to convert.
 * @param pLookupTable Lookup table to use.
 * @param nullTerminator Indicates if a null terminator should be added.
 * @returns The converted string.
 */
static std::vector<char> ToSBCSEncoding(const String &str,
                                        const uint8_t *pLookupTable,
                                        bool nullTerminator = true);

/**
 * Convert the @ref String to a double byte character set (DBCS) encoded string.
 * @param str String to convert.
 * @param pLookupTable Lookup table to use.
 * @param lookupTableArraySize Size (in elements) of the lookup table.
 * @param nullTerminator Indicates if a null terminator should be added.
 * @returns The converted string.
 */
static std::vector<char> ToDBCSEncoding(const String &str,
                                        const uint8_t *pLookupTable,
                                        size_t lookupTableArraySize,
                                        bool nullTerminator = true);

static String FromSBCSEncoding(const uint8_t *szString, int size,
                               const uint8_t *pLookupTable) {
  // If the size is 0, return an empty string. If the size is less than 0,
  // read as much as possible. In this case we will limit the string to the
  // max size of an integer (which is so huge it should not be reached).
  // Chances are the String class will barf if you try to create a string
  // that big.
  if (0 == size) {
    return String();
  } else if (0 > size) {
    size = INT_MAX;
  }

  // Obtain pointers to the lookup table so it may be used as an array of
  // unsigned 16-bit values.
  const uint16_t *pMappingTo = (uint16_t *)pLookupTable;
  const uint16_t *pMappingFrom = pMappingTo + 65536;

  // String to store the converted string into.
  String final;

  // Loop over the string until the null terminator has been or the
  // requested size has been reached.
  while (0 < size-- && 0 != *szString) {
    // Retrieve the next byte of the string and determine the mapped code
    // point for the desired encoding. Advance the pointer to the next
    // value in the source string.
    uint16_t SBCS = *(szString++);

    String::CodePoint unicode = pMappingFrom[SBCS];

    // If there is no mapped codec, return an empty string to indicate an
    // error.
    if (0 == unicode) {
      return String();
    }

    // Append the mapped code point to the string.
    final += String::FromCodePoint(unicode);
  }

  // Return the converted string.
  return final;
}

static String FromDBCSEncoding(const uint8_t *szString, int size,
                               const uint8_t *pLookupTable) {
  // If the size is 0, return an empty string. If the size is less than 0,
  // read as much as possible. In this case we will limit the string to the
  // max size of an integer (which is so huge it should not be reached).
  // Chances are the String class will barf if you try to create a string
  // that big.
  if (0 == size) {
    return String();
  } else if (0 > size) {
    size = INT_MAX;
  }

  // Obtain pointers to the lookup table so it may be used as an array of
  // unsigned 16-bit values.
  const uint16_t *pMappingTo = (uint16_t *)pLookupTable;
  const uint16_t *pMappingFrom = pMappingTo + 65536;

  // String to store the converted string into.
  String final;

  // Loop over the string until the null terminator has been or the
  // requested size has been reached.
  while (0 < size-- && 0 != *szString) {
    // Retrieve the next byte of the string and determine the mapped code
    // point for the desired encoding. DBCS is a multi-byte format similar
    // to Shift-JIS. As such, if the most significant bit is set, another
    // byte needs to be read and added to the code point before conversion.
    // After each byte read from the string, the string pointer should be
    // advanced.
    uint16_t DBCS = *(szString++);

    // Certain byte values indicate multibyte characters.
    if ((0x81 <= DBCS && 0x9F >= DBCS) || (0xE0 <= DBCS && 0xFC >= DBCS)) {
      // Sanity check that we can read the 2nd byte of the code point.
      // If not, we should return an empty string to indicate an error.
      /// @todo Consider throwing an exception as well (conversion
      /// exceptions should be enabled by a \#define).
      if (1 > size--) {
        return String();
      }

      // A multi-byte DBCS code point consists of the first byte in the
      // 8 most significant bits and the second byte in the 8 least
      // significant bits.
      DBCS = (uint16_t)((DBCS << 8) | *(szString++));
    }

    // If there is no mapped codec, return an empty string to indicate an
    // error.
    String::CodePoint unicode = pMappingFrom[DBCS];

    if (0 == unicode) {
      return String();
    }

    // Append the mapped code point to the string.
    final += String::FromCodePoint(unicode);
  }

  // Return the converted string.
  return final;
}

static std::vector<char> ToSBCSEncoding(const String &str,
                                        const uint8_t *pLookupTable,
                                        bool nullTerminator) {
  // Obtain a pointer to the lookup table so it may be used as an array of
  // unsigned 16-bit values.
  const uint16_t *pMappingTo = (uint16_t *)pLookupTable;

  // Used to add a null terminator to the end of the byte array.
  char zero = 0;

  // String to store the converted string into.
  std::vector<char> final;

  // Loop over every character in the source string.
  for (size_t i = 0; i < str.Length(); ++i) {
    // Get the Unicode code point for the current character.
    String::CodePoint unicode = str.At(i);

    // Find the mapped code point for the desired encoding.
    uint16_t SBCS = pMappingTo[unicode];

    // Add the converted character to the final string.
    final.push_back((char)(SBCS & 0xFF));
  }

  // Append a null terminator to the end of the final string.
  if (nullTerminator) {
    final.push_back(zero);
  }

  // Return the converted string.
  return final;
}

static std::vector<char> ToDBCSEncoding(const String &str,
                                        const uint8_t *pLookupTable,
                                        size_t lookupTableArraySize,
                                        bool nullTerminator) {
  // Obtain a pointer to the lookup table so it may be used as an array of
  // unsigned 16-bit values.
  const uint16_t *pMappingTo = (uint16_t *)pLookupTable;

  // Used to add a null terminator to the end of the byte array.
  char zero = 0;

  // String to store the converted string into.
  std::vector<char> final;

  // Loop over every character in the source string.
  for (size_t i = 0; i < str.Length(); ++i) {
    // Get the Unicode code point for the current character.
    String::CodePoint unicode = str.At(i);

    // Sanity check the code point is inside the array.
    if (lookupTableArraySize <= unicode ||
        (String::CodePoint)0xFFFF < unicode) {
      Exception e(
          String("Invalid character %1 in string: %2\n").Arg(i).Arg(str),
          __FILE__, __LINE__);
      e.Log();

      final.push_back('?');
      continue;
    }

    // Find the mapped code point for the desired encoding.
    uint16_t DBCS = pMappingTo[unicode];

    // If the most significant bit is set, this DBCS code point is a
    // multi-byte codepoint.
    if (0xFF < DBCS) {
      // Double byte, ensure the value is in big endian host order.
      DBCS = htobe16(DBCS);

      // Write two bytes to the final string.
      final.push_back((char)(DBCS & 0xFF));
      final.push_back((char)((DBCS >> 8) & 0xFF));
    } else {
      // Single byte, write one byte to the final string.
      final.push_back((char)(DBCS & 0xFF));
    }
  }

  // Append a null terminator to the end of the final string.
  if (nullTerminator) {
    final.push_back(zero);
  }

  // Return the converted string.
  return final;
}

String Convert::FromEncoding(Encoding_t encoding, const char *szString,
                             int size) {
  if (ENCODING_DEFAULT == encoding) {
    encoding = GetDefaultEncoding();
  }

  // Determine the function to call based on the encoding requested.
  switch (encoding) {
    case ENCODING_CP874:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP874);
    case ENCODING_CP932:
      return FromDBCSEncoding((uint8_t *)szString, size, LookupTableCP932);
    case ENCODING_CP936:
      return FromDBCSEncoding((uint8_t *)szString, size, LookupTableCP936);
    case ENCODING_CP949:
      return FromDBCSEncoding((uint8_t *)szString, size, LookupTableCP949);
    case ENCODING_CP950:
      return FromDBCSEncoding((uint8_t *)szString, size, LookupTableCP950);
    case ENCODING_CP1250:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1250);
    case ENCODING_CP1251:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1251);
    case ENCODING_CP1252:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1252);
    case ENCODING_CP1253:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1253);
    case ENCODING_CP1254:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1254);
    case ENCODING_CP1255:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1255);
    case ENCODING_CP1256:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1256);
    case ENCODING_CP1257:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1257);
    case ENCODING_CP1258:
      return FromSBCSEncoding((uint8_t *)szString, size, LookupTableCP1258);
    case ENCODING_CP1361:
      return FromDBCSEncoding((uint8_t *)szString, size, LookupTableCP1361);
    default:
      break;
  }

  // Default to a UTF-8 encoded string.
  if (0 > size) {
    return String(szString);
  } else {
    return String(szString, (size_t)size);
  }
}

String Convert::FromEncoding(Encoding_t encoding,
                             const std::vector<char> &str) {
  return str.size() > 0 ? FromEncoding(encoding, &str[0], (int)str.size())
                        : String();
}

std::vector<char> Convert::ToEncoding(Encoding_t encoding, const String &str,
                                      bool nullTerminator) {
  if (ENCODING_DEFAULT == encoding) {
    encoding = GetDefaultEncoding();
  }

  // Determine the function to call based on the encoding requested.
  switch (encoding) {
    case ENCODING_CP874:
      return ToSBCSEncoding(str, LookupTableCP874, nullTerminator);
    case ENCODING_CP932:
      return ToDBCSEncoding(str, LookupTableCP932, ARRAY_SIZE(LookupTableCP932),
                            nullTerminator);
    case ENCODING_CP936:
      return ToDBCSEncoding(str, LookupTableCP936, ARRAY_SIZE(LookupTableCP936),
                            nullTerminator);
    case ENCODING_CP949:
      return ToDBCSEncoding(str, LookupTableCP949, ARRAY_SIZE(LookupTableCP949),
                            nullTerminator);
    case ENCODING_CP950:
      return ToDBCSEncoding(str, LookupTableCP950, ARRAY_SIZE(LookupTableCP950),
                            nullTerminator);
    case ENCODING_CP1250:
      return ToSBCSEncoding(str, LookupTableCP1250, nullTerminator);
    case ENCODING_CP1251:
      return ToSBCSEncoding(str, LookupTableCP1251, nullTerminator);
    case ENCODING_CP1252:
      return ToSBCSEncoding(str, LookupTableCP1252, nullTerminator);
    case ENCODING_CP1253:
      return ToSBCSEncoding(str, LookupTableCP1253, nullTerminator);
    case ENCODING_CP1254:
      return ToSBCSEncoding(str, LookupTableCP1254, nullTerminator);
    case ENCODING_CP1255:
      return ToSBCSEncoding(str, LookupTableCP1255, nullTerminator);
    case ENCODING_CP1256:
      return ToSBCSEncoding(str, LookupTableCP1256, nullTerminator);
    case ENCODING_CP1257:
      return ToSBCSEncoding(str, LookupTableCP1257, nullTerminator);
    case ENCODING_CP1258:
      return ToSBCSEncoding(str, LookupTableCP1258, nullTerminator);
    case ENCODING_CP1361:
      return ToDBCSEncoding(str, LookupTableCP1361,
                            ARRAY_SIZE(LookupTableCP1361), nullTerminator);
    default:
      break;
  }

  // Default to a UTF-8 encoded string.
  return str.Data(nullTerminator);
}

size_t Convert::SizeEncoded(Encoding_t encoding, const String &str,
                            size_t align) {
  // Convert the string to determine the size of the encoded result.
  std::vector<char> out = ToEncoding(encoding, str, false);

  // If the string should be aligned, calculate the aligned size.
  if (0 < align) {
    return ((out.size() + align - 1) / align) * align;
  }

  // Return the size of the encoded string without alignment.
  return out.size();
}

std::list<String> Convert::AvailableEncodings() {
  return {
      "utf8",   "cp874",  "cp932",  "cp936",  "cp949",  "cp950",
      "cp1250", "cp1251", "cp1252", "cp1253", "cp1254", "cp1255",
      "cp1256", "cp1257", "cp1258", "cp1361",
  };
}

Convert::Encoding_t Convert::EncodingFromString(const String &name) {
  static EnumMap<String, Convert::Encoding_t> mapping = {
      {"utf8", Convert::Encoding_t::ENCODING_UTF8},
      {"cp874", Convert::Encoding_t::ENCODING_CP874},
      {"cp932", Convert::Encoding_t::ENCODING_CP932},
      {"cp936", Convert::Encoding_t::ENCODING_CP936},
      {"cp949", Convert::Encoding_t::ENCODING_CP949},
      {"cp950", Convert::Encoding_t::ENCODING_CP950},
      {"cp1250", Convert::Encoding_t::ENCODING_CP1250},
      {"cp1251", Convert::Encoding_t::ENCODING_CP1251},
      {"cp1252", Convert::Encoding_t::ENCODING_CP1252},
      {"cp1253", Convert::Encoding_t::ENCODING_CP1253},
      {"cp1254", Convert::Encoding_t::ENCODING_CP1254},
      {"cp1255", Convert::Encoding_t::ENCODING_CP1255},
      {"cp1256", Convert::Encoding_t::ENCODING_CP1256},
      {"cp1257", Convert::Encoding_t::ENCODING_CP1257},
      {"cp1258", Convert::Encoding_t::ENCODING_CP1258},
      {"cp1361", Convert::Encoding_t::ENCODING_CP1361},
  };

  auto it = mapping.find(name);

  if (it != mapping.end()) {
    return it->second;
  } else {
    return Convert::Encoding_t::ENCODING_DEFAULT;
  }
}

String Convert::EncodingToString(Convert::Encoding_t encoding) {
  static EnumMap<Convert::Encoding_t, String> mapping = {
      {Convert::Encoding_t::ENCODING_DEFAULT, "default"},
      {Convert::Encoding_t::ENCODING_UTF8, "utf8"},
      {Convert::Encoding_t::ENCODING_CP874, "cp874"},
      {Convert::Encoding_t::ENCODING_CP932, "cp932"},
      {Convert::Encoding_t::ENCODING_CP936, "cp936"},
      {Convert::Encoding_t::ENCODING_CP949, "cp949"},
      {Convert::Encoding_t::ENCODING_CP950, "cp950"},
      {Convert::Encoding_t::ENCODING_CP1250, "cp1250"},
      {Convert::Encoding_t::ENCODING_CP1251, "cp1251"},
      {Convert::Encoding_t::ENCODING_CP1252, "cp1252"},
      {Convert::Encoding_t::ENCODING_CP1253, "cp1253"},
      {Convert::Encoding_t::ENCODING_CP1254, "cp1254"},
      {Convert::Encoding_t::ENCODING_CP1255, "cp1255"},
      {Convert::Encoding_t::ENCODING_CP1256, "cp1256"},
      {Convert::Encoding_t::ENCODING_CP1257, "cp1257"},
      {Convert::Encoding_t::ENCODING_CP1258, "cp1258"},
      {Convert::Encoding_t::ENCODING_CP1361, "cp1361"},
  };

  auto it = mapping.find(encoding);

  if (it != mapping.end()) {
    return it->second;
  } else {
    return "default";
  }
}

Convert::Encoding_t Convert::GetDefaultEncoding() { return gDefaultEncoding; }

void Convert::SetDefaultEncoding(Convert::Encoding_t encoding) {
  gDefaultEncoding = encoding;
}
