/**
 * @file libobjgen/tests/UUID.cpp
 * @ingroup libobjgen
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Test the UUID class against the Cassandra implementation.
 *
 * This file is part of the COMP_hack Object Generator Library (libobjgen).
 *
 * Copyright (C) 2014-2016 COMP_hack Team <compomega@tutanota.com>
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

#include <PushIgnore.h>
#include <gtest/gtest.h>
#include <PopIgnore.h>

// libobjgen Includes
#include <UUID.h>

using namespace libobjgen;

TEST(UUID, Null)
{
    CassUuid cassUUID;
    cassUUID.time_and_version = 0;
    cassUUID.clock_seq_and_node = 0;

    EXPECT_TRUE(UUID().IsNull());
    EXPECT_TRUE(UUID("00000000-0000-0000-0000-000000000000").IsNull());
    EXPECT_TRUE(UUID(cassUUID).IsNull());

    EXPECT_FALSE(UUID("00000001-0000-0000-0000-000000000000").IsNull());
    EXPECT_FALSE(UUID("00000000-0000-0000-0000-000000000001").IsNull());

    cassUUID.time_and_version = 1;
    cassUUID.clock_seq_and_node = 0;
    EXPECT_FALSE(UUID(cassUUID).IsNull());

    cassUUID.time_and_version = 0;
    cassUUID.clock_seq_and_node = 1;
    EXPECT_FALSE(UUID(cassUUID).IsNull());

    cassUUID.time_and_version = 1;
    cassUUID.clock_seq_and_node = 1;
    EXPECT_FALSE(UUID(cassUUID).IsNull());
}

TEST(UUID, Compare)
{
    CassUuid cassUUID;
    CassUuid cassUUID2;

    CassUuidGen *pGenerator = cass_uuid_gen_new();
    cass_uuid_gen_random(pGenerator, &cassUUID);
    cass_uuid_gen_random(pGenerator, &cassUUID2);

    UUID libcompUUID(cassUUID);
    UUID libcompUUID2(cassUUID2);

    EXPECT_EQ(libcompUUID, libcompUUID);
    EXPECT_EQ(libcompUUID, cassUUID);
    EXPECT_EQ(libcompUUID.ToCassandra().time_and_version,
        cassUUID.time_and_version);
    EXPECT_EQ(libcompUUID.ToCassandra().clock_seq_and_node,
        cassUUID.clock_seq_and_node);

    EXPECT_NE(libcompUUID2, libcompUUID);
    EXPECT_NE(libcompUUID2, cassUUID);
    EXPECT_NE(libcompUUID2.ToCassandra().time_and_version,
        cassUUID.time_and_version);
    EXPECT_NE(libcompUUID2.ToCassandra().clock_seq_and_node,
        cassUUID.clock_seq_and_node);

    EXPECT_NE(libcompUUID, libcompUUID2);
    EXPECT_NE(libcompUUID, cassUUID2);
    EXPECT_NE(libcompUUID.ToCassandra().time_and_version,
        cassUUID2.time_and_version);
    EXPECT_NE(libcompUUID.ToCassandra().clock_seq_and_node,
        cassUUID2.clock_seq_and_node);

    cass_uuid_gen_free(pGenerator);
}

TEST(UUID, StringConversion)
{
    CassUuid cassUUID;
    char uuidString[CASS_UUID_STRING_LENGTH];

    CassUuidGen *pGenerator = cass_uuid_gen_new();
    cass_uuid_gen_random(pGenerator, &cassUUID);
    cass_uuid_string(cassUUID, uuidString);

    EXPECT_EQ(UUID(uuidString), cassUUID);
    EXPECT_EQ(UUID(uuidString).ToString(), uuidString);

    cass_uuid_gen_free(pGenerator);
}

TEST(UUID, Generate)
{
    UUID a = UUID::Random();
    UUID b = UUID::Random();

    EXPECT_FALSE(a.IsNull());
    EXPECT_FALSE(b.IsNull());

    EXPECT_EQ(cass_uuid_version(a.ToCassandra()), 4);
    EXPECT_EQ(cass_uuid_version(b.ToCassandra()), 4);

    EXPECT_NE(a, b);
}

TEST(UUID, BinaryConversion)
{
    std::string uuidString = "e70ebdd0-7a79-4bff-9e1f-1d8c0a3a6fb6";

    unsigned char uuidData[] = {
        0xe7, 0x0e, 0xbd, 0xd0, 0x7a, 0x79, 0x4b, 0xff,
        0x9e, 0x1f, 0x1d, 0x8c, 0x0a, 0x3a, 0x6f, 0xb6,
    };

    UUID uuid(std::vector<char>((char*)uuidData,
        (char*)uuidData + sizeof(uuidData)));

    EXPECT_EQ(uuid.ToString(), uuidString);

    std::vector<char> uuidDataCopy = uuid.ToData();

    ASSERT_EQ(uuidDataCopy.size(), sizeof(uuidData));
    EXPECT_EQ(UUID(uuidDataCopy).ToString(), uuidString);
    EXPECT_EQ(memcmp(&uuidDataCopy[0], &uuidData[0], sizeof(uuidData)), 0);
}

int main(int argc, char *argv[])
{
    try
    {
        ::testing::InitGoogleTest(&argc, argv);

        return RUN_ALL_TESTS();
    }
    catch(...)
    {
        return EXIT_FAILURE;
    }
}
