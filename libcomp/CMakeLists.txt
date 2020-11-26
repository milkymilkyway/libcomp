# This file is part of COMP_hack.
#
# Copyright (C) 2010-2020 COMP_hack Team <compomega@tutanota.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(libcomp)

# Assume built-in pthreads on MacOS
# https://stackoverflow.com/questions/54587052/
IF(APPLE)
    SET(CMAKE_THREAD_LIBS_INIT "-lpthread")
    SET(CMAKE_HAVE_THREADS_LIBRARY 1)
    SET(CMAKE_USE_WIN32_THREADS_INIT 0)
    SET(CMAKE_USE_PTHREADS_INIT 1)
    SET(THREADS_PREFER_PTHREAD_FLAG ON)
ELSE()
    FIND_PACKAGE(Threads REQUIRED)
ENDIF()

MESSAGE("** Configuring ${PROJECT_NAME} **")

# Add a target to generate API documentation.
FILE(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/api/libcomp)
GENERATE_DOCS(doc/Doxyfile.in)

# Add a directory to put the objgen output into.
FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/objgen)

SET(SYSTEM_LIBRARIES "")

IF(BSD)
FIND_PACKAGE(ExecInfo REQUIRED)

SET(SYSTEM_LIBRARIES ${SYSTEM_LIBRARIES} ${EXECINFO_LIBRARY})
ENDIF(BSD)

# Write the version information into the Constants.h file.
CONFIGURE_FILE(src/Constants.h.in "${CMAKE_CURRENT_BINARY_DIR}/Constants.h"
    ESCAPE_QUOTES @ONLY NEWLINE_STYLE UNIX)

SET(${PROJECT_NAME}_SRCS
    src/ArgumentParser.cpp
    src/BaseServer.cpp
    src/BinaryDataSet.cpp
    src/ChannelConnection.cpp
    src/Compress.cpp
    src/Convert.cpp
    src/Crypto.cpp
    src/CString.cpp
    src/Database.cpp
    src/DatabaseBind.cpp
    src/DatabaseChangeSet.cpp
    src/DatabaseMariaDB.cpp
    src/DatabaseQuery.cpp
    src/DatabaseQueryMariaDB.cpp
    src/DatabaseQuerySQLite3.cpp
    src/DatabaseSQLite3.cpp
    src/DataFile.cpp
    src/DataStore.cpp
    src/DataSyncManager.cpp
    src/DefinitionManager.cpp
    src/DynamicObject.cpp
    src/DynamicVariable.cpp
    src/DynamicVariableFactory.cpp
    src/EncryptedConnection.cpp
    src/ErrorCodes.cpp
    src/Exception.cpp
    src/InternalConnection.cpp
    src/LobbyConnection.cpp
    src/Log.cpp
    src/ManagerPacket.cpp
    #src/MemoryFile.cpp
    src/MemoryManager.cpp
    src/MessageConnectionClosed.cpp
    src/MessageEncrypted.cpp
    src/MessageInit.cpp
    src/MessagePacket.cpp
    src/MessagePong.cpp
    src/MessageShutdown.cpp
    src/MessageTimeout.cpp
    src/MessageWorldNotification.cpp
    src/Mutex.cpp
    src/Object.cpp
    src/Packet.cpp
    src/PacketException.cpp
    #src/PacketScript.cpp
    src/PlatformWindows.cpp
    src/PEFile.cpp
    src/PersistentObject.cpp
    src/Randomizer.cpp
    src/ReadOnlyPacket.cpp
    #src/RingBuffer.cpp
    src/ScriptEngine.cpp
    src/ServerCommandLineParser.cpp
    src/ServerConstants.cpp
    src/ServerDataManager.cpp
    src/Shutdown.cpp
    src/SqratInt64.cpp
    #src/Structgen.cpp
    src/TcpConnection.cpp
    src/TcpServer.cpp
    #src/ThreadManager.cpp
    src/TimerManager.cpp
    src/WindowsService.cpp
    src/Worker.cpp

    # Red-black tree for memory manager.
    src/rbtree.c

    # ASIO sources for exotic platforms.
    ${ASIO_SRCS}
)

IF(NOT WIN32 AND NOT APPLE AND NOT BUILD_EXOTIC)
    SET(${PROJECT_NAME}_SRCS
        ${${PROJECT_NAME}_SRCS}
        # for comp_manager and testing.
        src/Child.cpp
        src/DayCare.cpp
        src/SpawnThread.cpp
        src/WatchThread.cpp
    )
ENDIF(NOT WIN32 AND NOT APPLE AND NOT BUILD_EXOTIC)

IF(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/ConfigCustom.cpp)
    SET(${PROJECT_NAME}_SRCS ${${PROJECT_NAME}_SRCS} src/ConfigCustom.cpp)
ELSE()
    SET(${PROJECT_NAME}_SRCS ${${PROJECT_NAME}_SRCS} src/Config.cpp)
ENDIF()

# This is a list of all header files. Adding the header files here ensures they
# are listed in the source files for IDE projects.
SET(${PROJECT_NAME}_HDRS
    "${CMAKE_CURRENT_BINARY_DIR}/Constants.h"

    src/ArgumentParser.h
    src/BaseServer.h
    src/BinaryDataSet.h
    src/ChannelConnection.h
    src/Compress.h
    src/ConnectionMessage.h
    src/Convert.h
    src/CryptSupport.h
    src/CString.h
    src/Database.h
    src/DatabaseBind.h
    src/DatabaseChangeSet.h
    src/DatabaseMariaDB.h
    src/DatabaseQuery.h
    src/DatabaseQueryMariaDB.h
    src/DatabaseQuerySQLite3.h
    src/DatabaseSQLite3.h
    src/DataFile.h
    src/DataStore.h
    src/DataSyncManager.h
    src/Crypto.h
    src/DefinitionManager.h
    src/DynamicObject.h
    src/DynamicVariable.h
    src/DynamicVariableFactory.h
    src/DynamicVariableInt.h
    src/EncryptedConnection.h
    src/Endian.h
    src/EnumMap.h
    src/EnumUtils.h
    src/ErrorCodes.h
    src/Exception.h
    src/InternalConnection.h
    src/LobbyConnection.h
    src/Log.h
    src/Manager.h
    src/ManagerPacket.h
    #src/MemoryFile.h
    src/MemoryManager.h
    src/Message.h
    src/MessageConnectionClosed.h
    src/MessageEncrypted.h
    src/MessageExecute.h
    src/MessageInit.h
    src/MessagePacket.h
    src/MessagePong.h
    src/MessageQueue.h
    src/MessageShutdown.h
    src/MessageTick.h
    src/MessageTimeout.h
    src/MessageWorldNotification.h
    src/Mutex.h
    src/Object.h
    src/ObjectReference.h
    src/Packet.h
    src/PacketCodes.h
    src/PacketException.h
    src/PacketParser.h
    #src/PacketScript.h
    src/PacketStream.h
    src/PEFile.h
    src/PEFormat.h
    src/PersistentObject.h
    #src/Platform.h
    #src/PlatformLinux.h
    #src/PlatformWindows.h
    src/Randomizer.h
    src/ReadOnlyPacket.h
    src/RingBuffer.h
    src/ScriptEngine.h
    src/ServerCommandLineParser.h
    src/ServerConstants.h
    src/ServerDataManager.h
    src/Shutdown.h
    src/TcpConnection.h
    src/TcpServer.h
    #src/ThreadManager.h
    src/TimerManager.h
    src/WindowsService.h
    src/Worker.h

    # These were generated and are not worth reading.
    src/LookupTableCP1252.h
    src/LookupTableCP932.h

    # Macros to temporarily disable warnings (wrapped around 3rd party libs).
    src/PushIgnore.h
    src/PopIgnore.h

    # Red-black tree for memory manager.
    src/rbtree.h
)

IF(NOT WIN32 AND NOT APPLE AND NOT BUILD_EXOTIC)
    SET(${PROJECT_NAME}_HDRS
        ${${PROJECT_NAME}_HDRS}
        # for comp_manager and testing.
        src/Child.h
        src/DayCare.h
        src/SpawnThread.h
        src/WatchThread.h
    )
ENDIF(NOT WIN32 AND NOT APPLE AND NOT BUILD_EXOTIC)

SET(${PROJECT_NAME}_SCHEMA
    schema/account.xml
    schema/accountlogin.xml
    schema/action.xml
    schema/action_addremoveitems.xml
    schema/action_addremovestatus.xml
    schema/action_createloot.xml
    schema/action_delay.xml
    schema/action_displaymessage.xml
    schema/action_grantskills.xml
    schema/action_grantxp.xml
    schema/action_homepoint.xml
    schema/action_playbgm.xml
    schema/action_playsoundeffect.xml
    schema/action_runscript.xml
    schema/action_setnpcstate.xml
    schema/action_spawn.xml
    schema/action_specialdirection.xml
    schema/action_stageeffect.xml
    schema/action_startevent.xml
    schema/action_updatecomp.xml
    schema/action_updateflag.xml
    schema/action_updatelnc.xml
    schema/action_updatepoints.xml
    schema/action_updatequest.xml
    schema/action_updatezoneflags.xml
    schema/action_zonechange.xml
    schema/action_zoneinstance.xml
    schema/ailogic.xml
    schema/character.xml
    schema/clan.xml
    schema/databaseconfig.xml
    schema/databaseconfig_mariadb.xml
    schema/databaseconfig_sqlite3.xml
    schema/demon.xml
    schema/enemy.xml
    schema/event.xml
    schema/event_direction.xml
    schema/event_message.xml
    schema/event_openmenu.xml
    schema/event_performactions.xml
    schema/event_playscene.xml
    schema/event_prompt.xml
    schema/fusion.xml
    schema/item.xml
    schema/match.xml
    schema/packet_login.xml
    schema/packet_login_reply.xml
    schema/packet_response_code.xml
    schema/party.xml
    schema/promo.xml
    schema/qmp_file.xml
    schema/registeredchannel.xml
    schema/registeredworld.xml
    schema/reportedplayer.xml
    schema/server_command_line.xml
    schema/server_npc.xml
    schema/server_object.xml
    schema/server_shop.xml
    schema/server_zone.xml
    schema/serverconfig.xml
    schema/search.xml
    schema/spawn.xml
    schema/team.xml
    schema/test.xml
    schema/tokusei.xml
    schema/ultimatebattle.xml
    schema/webgame.xml

    # BinaryData Files
    schema/binarydata/aidata.xml
    schema/binarydata/actionlogicdata.xml
    schema/binarydata/autolivedata.xml
    schema/binarydata/bazaarclerknpcdata.xml
    schema/binarydata/blenddata.xml
    schema/binarydata/cblocknamedata.xml
    schema/binarydata/cchanceitemdata.xml
    schema/binarydata/cculturedata.xml
    schema/binarydata/cdevilbookbonusdata.xml
    schema/binarydata/cdevilbookbonusmitamadata.xml
    schema/binarydata/cdevilboosticondata.xml
    schema/binarydata/cdevildungeondata.xml
    schema/binarydata/cdevilequipmentexclusivedata.xml
    schema/binarydata/cequipmodeldata.xml
    schema/binarydata/ceventdata.xml
    schema/binarydata/ceventmessagedata.xml
    schema/binarydata/cguardianassistdata.xml
    schema/binarydata/cguidedata.xml
    schema/binarydata/cfortunedata.xml
    schema/binarydata/chanceitemdata.xml
    schema/binarydata/chelpdata.xml
    schema/binarydata/chouraidata.xml
    schema/binarydata/cicondata.xml
    schema/binarydata/citemdata.xml
    schema/binarydata/ckeyitemdata.xml
    schema/binarydata/cloadingcommercialdata.xml
    schema/binarydata/cmapdata.xml
    schema/binarydata/cmessagedata.xml
    schema/binarydata/cmodeldata.xml
    schema/binarydata/cmodifiedeffectdata.xml
    schema/binarydata/cmultitalkdata.xml
    schema/binarydata/cnakamaquestrewarddata.xml
    schema/binarydata/codenamedata.xml
    schema/binarydata/cpolygonmoviedata.xml
    schema/binarydata/cquest.xml
    schema/binarydata/cskilldata.xml
    schema/binarydata/csounddata.xml
    schema/binarydata/cspecialskilleffectdata.xml
    schema/binarydata/cstatusdata.xml
    schema/binarydata/csynthesiscatalystdata.xml
    schema/binarydata/ctalkmessagedata.xml
    schema/binarydata/ctimeattackdata.xml
    schema/binarydata/ctitledata.xml
    schema/binarydata/ctransformedmodeldata.xml
    schema/binarydata/cultureitemdata.xml
    schema/binarydata/curafielddata.xml
    schema/binarydata/cvaluabledata.xml
    schema/binarydata/cvaluablesdata.xml
    schema/binarydata/czonerelationdata.xml
    schema/binarydata/deunionitemcatalystdata.xml
    schema/binarydata/devilbookbonusdata.xml
    schema/binarydata/devilbookbonusmitamadata.xml
    schema/binarydata/devilbookdata.xml
    schema/binarydata/devilboostdata.xml
    schema/binarydata/devildata.xml
    schema/binarydata/devilequipmentdata.xml
    schema/binarydata/devillvupratedata.xml
    schema/binarydata/disassemblydata.xml
    schema/binarydata/dynamicmapdata.xml
    schema/binarydata/enchantdata.xml
    schema/binarydata/enchantinitializedata.xml
    schema/binarydata/enchantpiercingdata.xml
    schema/binarydata/equipmentsetdata.xml
    schema/binarydata/eventdirectiondata.xml
    schema/binarydata/exchangedata.xml
    schema/binarydata/expertdata.xml
    schema/binarydata/experttitledata.xml
    schema/binarydata/fusiondata.xml
    schema/binarydata/guardiandata.xml
    schema/binarydata/gvgdata.xml
    schema/binarydata/gvgtrophydata.xml
    schema/binarydata/hnpcdata.xml
    schema/binarydata/itemdata.xml
    schema/binarydata/missiondata.xml
    schema/binarydata/mitamadata.xml
    schema/binarydata/modificationcatalystdata.xml
    schema/binarydata/modificationdata.xml
    schema/binarydata/modificationextcatalystdata.xml
    schema/binarydata/npcbarterdata.xml
    schema/binarydata/npcinvisibledata.xml
    schema/binarydata/onpcdata.xml
    schema/binarydata/questbonusdata.xml
    schema/binarydata/questdata.xml
    schema/binarydata/reporttypedata.xml
    schema/binarydata/shared.xml
    schema/binarydata/shopproductdata.xml
    schema/binarydata/sitemdata.xml
    schema/binarydata/skilldata.xml
    schema/binarydata/slotinitializedata.xml
    schema/binarydata/slotpiercingdata.xml
    schema/binarydata/spotdata.xml
    schema/binarydata/sstatusdata.xml
    schema/binarydata/statusdata.xml
    schema/binarydata/tankdata.xml
    schema/binarydata/timelimitdata.xml
    schema/binarydata/triunionkreuzitemdata.xml
    schema/binarydata/triunionspecialdata.xml
    schema/binarydata/uiinfodata.xml
    schema/binarydata/ultimatebattlebasedata.xml
    schema/binarydata/unionitemshelperdata.xml
    schema/binarydata/urafieldtowerdata.xml
    schema/binarydata/warppointdata.xml
    schema/binarydata/worlddata.xml
    schema/binarydata/zonedata.xml
)

SOURCE_GROUP("objgen" ${CMAKE_CURRENT_BINARY_DIR}/objgen/*)

OBJGEN_XML(${PROJECT_NAME}_STRUCTS
    # Main schema
    schema/libcomp-master.xml

    # Included schemas
    ${${PROJECT_NAME}_SCHEMA}

    # Include paths
    schema

    # Output files
    Account.h
    Account.cpp
    AccountLogin.h
    AccountLogin.cpp
    AccountWorldData.h
    AccountWorldData.cpp
    Action.h
    Action.cpp
    ActionAddRemoveItems.h
    ActionAddRemoveItems.cpp
    ActionAddRemoveStatus.h
    ActionAddRemoveStatus.cpp
    ActionCreateLoot.h
    ActionCreateLoot.cpp
    ActionDelay.h
    ActionDelay.cpp
    ActionDisplayMessage.h
    ActionDisplayMessage.cpp
    ActionGrantSkills.h
    ActionGrantSkills.cpp
    ActionGrantXP.h
    ActionGrantXP.cpp
    ActionPlayBGM.h
    ActionPlayBGM.cpp
    ActionPlaySoundEffect.h
    ActionPlaySoundEffect.cpp
    ActionRunScript.h
    ActionRunScript.cpp
    ActionSetHomepoint.h
    ActionSetHomepoint.cpp
    ActionSetNPCState.h
    ActionSetNPCState.cpp
    ActionSpawn.h
    ActionSpawn.cpp
    ActionSpecialDirection.h
    ActionSpecialDirection.cpp
    ActionStageEffect.h
    ActionStageEffect.cpp
    ActionStartEvent.h
    ActionStartEvent.cpp
    ActionUpdateCOMP.h
    ActionUpdateCOMP.cpp
    ActionUpdateFlag.h
    ActionUpdateFlag.cpp
    ActionUpdateLNC.h
    ActionUpdateLNC.cpp
    ActionUpdatePoints.h
    ActionUpdatePoints.cpp
    ActionUpdateQuest.h
    ActionUpdateQuest.cpp
    ActionUpdateZoneFlags.h
    ActionUpdateZoneFlags.cpp
    ActionZoneInstance.h
    ActionZoneInstance.cpp
    ActionZoneChange.h
    ActionZoneChange.cpp
    AILogicGroup.h
    AILogicGroup.cpp
    BazaarData.h
    BazaarData.cpp
    BazaarItem.h
    BazaarItem.cpp
    Clan.h
    Clan.cpp
    ClanInfo.h
    ClanInfo.cpp
    ClanMember.h
    ClanMember.cpp
    ChannelLogin.h
    ChannelLogin.cpp
    CharacterLogin.h
    CharacterLogin.cpp
    CharacterProgress.h
    CharacterProgress.cpp
    CultureData.h
    CultureData.cpp
    PvPData.h
    PvPData.cpp
    DatabaseConfig.h
    DatabaseConfig.cpp
    DatabaseConfigMariaDB.h
    DatabaseConfigMariaDB.cpp
    DatabaseConfigSQLite3.h
    DatabaseConfigSQLite3.cpp
    EntityStats.h
    EntityStats.cpp
    EventCounter.h
    EventCounter.cpp
    Item.h
    Item.cpp
    Demon.h
    Demon.cpp
    Quest.h
    Quest.cpp
    DemonQuest.h
    DemonQuest.cpp
    Character.h
    Character.cpp
    DemonBox.h
    DemonBox.cpp
    DemonFamiliarityType.h
    DemonFamiliarityType.cpp
    DemonPresent.h
    DemonPresent.cpp
    DemonQuestReward.h
    DemonQuestReward.cpp
    DropSet.h
    DropSet.cpp
    EnemyExtension.h
    EnemyExtension.cpp
    EnemyBase.h
    EnemyBase.cpp
    Enemy.h
    Enemy.cpp
    Ally.h
    Ally.cpp
    EventConditionData.cpp
    EventConditionData.h
    EventCondition.h
    EventCondition.cpp
    EventBase.h
    EventBase.cpp
    EventSequence.h
    EventSequence.cpp
    Event.h
    Event.cpp
    EventChoice.h
    EventChoice.cpp
    EventDirection.h
    EventDirection.cpp
    EventExNPCMessage.h
    EventExNPCMessage.cpp
    EventFlagCondition.h
    EventFlagCondition.cpp
    EventITime.h
    EventITime.cpp
    EventMultitalk.h
    EventMultitalk.cpp
    EventNPCMessage.h
    EventNPCMessage.cpp
    EventOpenMenu.h
    EventOpenMenu.cpp
    EventPerformActions.h
    EventPerformActions.cpp
    EventPlayScene.h
    EventPlayScene.cpp
    EventPrompt.h
    EventPrompt.cpp
    EventScriptCondition.h
    EventScriptCondition.cpp
    Expertise.h
    Expertise.cpp
    FriendSettings.h
    FriendSettings.cpp
    FusionMistake.h
    FusionMistake.cpp
    Hotbar.h
    Hotbar.cpp
    InheritedSkill.h
    InheritedSkill.cpp
    InstanceAccess.h
    InstanceAccess.cpp
    ItemBox.h
    ItemBox.cpp
    ItemDrop.h
    ItemDrop.cpp
    Match.h
    Match.cpp
    MatchEntry.h
    MatchEntry.cpp
    ObjectPosition.h
    ObjectPosition.cpp
    PacketLogin.h
    PacketLogin.cpp
    PacketLoginReply.h
    PacketLoginReply.cpp
    PacketResponseCode.h
    PacketResponseCode.cpp
    Party.h
    Party.cpp
    PartyCharacter.h
    PartyCharacter.cpp
    PartyMember.h
    PartyMember.cpp
    PentalphaEntry.h
    PentalphaEntry.cpp
    PentalphaMatch.h
    PentalphaMatch.cpp
    PlasmaSpawn.h
    PlasmaSpawn.cpp
    PostItem.h
    PostItem.cpp
    Promo.h
    Promo.cpp
    PromoExchange.h
    PromoExchange.cpp
    PvPMatch.h
    PvPMatch.cpp
    QmpFile.h
    QmpFile.cpp
    QmpElement.h
    QmpElement.cpp
    QmpBoundary.h
    QmpBoundary.cpp
    QmpBoundaryLine.h
    QmpBoundaryLine.cpp
    QmpNavPoint.h
    QmpNavPoint.cpp
    RegisteredChannel.h
    RegisteredChannel.cpp
    RegisteredWorld.h
    RegisteredWorld.cpp
    ReportedPlayer.h
    ReportedPlayer.cpp
    SearchEntry.h
    SearchEntry.cpp
    ServerBazaar.h
    ServerBazaar.cpp
    ServerCommandLine.h
    ServerCommandLine.cpp
    ServerConfig.h
    ServerConfig.cpp
    ServerCultureMachineSet.h
    ServerCultureMachineSet.cpp
    ServerNPC.h
    ServerNPC.cpp
    ServerObject.h
    ServerObject.cpp
    ServerObjectBase.h
    ServerObjectBase.cpp
    ServerShop.h
    ServerShop.cpp
    ServerShopProduct.h
    ServerShopProduct.cpp
    ServerShopTab.h
    ServerShopTab.cpp
    ServerZone.h
    ServerZone.cpp
    ServerZoneInstance.h
    ServerZoneInstance.cpp
    ServerZoneInstanceVariant.h
    ServerZoneInstanceVariant.cpp
    PvPInstanceVariant.h
    PvPInstanceVariant.cpp
    ServerZonePartial.h
    ServerZonePartial.cpp
    ServerZoneSpot.h
    ServerZoneSpot.cpp
    ServerZoneTrigger.h
    ServerZoneTrigger.cpp
    StatusEffect.h
    StatusEffect.cpp
    Spawn.h
    Spawn.cpp
    SpawnGroup.h
    SpawnGroup.cpp
    SpawnLocation.h
    SpawnLocation.cpp
    SpawnLocationGroup.h
    SpawnLocationGroup.cpp
    SpawnRestriction.h
    SpawnRestriction.cpp
    Team.h
    Team.cpp
    TestObject.h
    TestObject.cpp
    TestObjectA.h
    TestObjectA.cpp
    TestObjectB.h
    TestObjectB.cpp
    TestObjectC.h
    TestObjectC.cpp
    TestObjectD.h
    TestObjectD.cpp
    TestObjectE.h
    TestObjectE.cpp
    Tokusei.h
    Tokusei.cpp
    TokuseiAspect.h
    TokuseiAspect.cpp
    TokuseiAttributes.h
    TokuseiAttributes.cpp
    TokuseiCondition.h
    TokuseiCondition.cpp
    TokuseiCorrectTbl.h
    TokuseiCorrectTbl.cpp
    TokuseiSkillCondition.h
    TokuseiSkillCondition.cpp
    UBTournament.h
    UBTournament.cpp
    UBResult.h
    UBResult.cpp
    WebGameSession.h
    WebGameSession.cpp
    WorldSharedConfig.h
    WorldSharedConfig.cpp

    # BinaryData Files
    MiAcquisitionData.cpp
    MiAcquisitionData.h
    MiAcquisitionSkillData.cpp
    MiAcquisitionSkillData.h
    MiAddStatusTbl.cpp
    MiAddStatusTbl.h
    MiAIData.cpp
    MiAIData.h
    MiAIRelationData.cpp
    MiAIRelationData.h
    MiActionLogicData.cpp
    MiActionLogicData.h
    MiActionTblData.cpp
    MiActionTblData.h
    MiAutoLiveData.cpp
    MiAutoLiveData.h
    MiBattleDamageData.cpp
    MiBattleDamageData.h
    MiBazaarClerkNPCData.h
    MiBazaarClerkNPCData.cpp
    MiBlendData.cpp
    MiBlendData.h
    MiBlendData_Item.cpp
    MiBlendData_Item.h
    MiBlendExtData.cpp
    MiBlendExtData.h
    MiBlendExtData_DstItemChange.cpp
    MiBlendExtData_DstItemChange.h
    MiBlendExtData_SrcItemChange.cpp
    MiBlendExtData_SrcItemChange.h
    MiBreakData.cpp
    MiBreakData.h
    MiCancelData.cpp
    MiCancelData.h
    MiCastBasicData.cpp
    MiCastBasicData.h
    MiCastCancelData.cpp
    MiCastCancelData.h
    MiCastData.cpp
    MiCastData.h
    MiCategoryData.h
    MiCategoryData.cpp
    MiCAppearanceEquipData.cpp
    MiCAppearanceEquipData.h
    MiCBlockNameData.cpp
    MiCBlockNameData.h
    MiCChanceItemData.h
    MiCChanceItemData.cpp
    MiCCultureData.h
    MiCCultureData.cpp
    MiCEventFrameTbl.cpp
    MiCEventFrameTbl.h
    MiCEventData.cpp
    MiCEventData.h
    MiCEventMessageData.cpp
    MiCEventMessageData.h
    MiCDevilBookBonusData.cpp
    MiCDevilBookBonusData.h
    MiCDevilBookBonusMitamaData.cpp
    MiCDevilBookBonusMitamaData.h
    MiCDevilBoostIconData.cpp
    MiCDevilBoostIconData.h
    MiCDevilDungeonData.cpp
    MiCDevilDungeonData.h
    MiCDevilEquipmentExclusiveData.cpp
    MiCDevilEquipmentExclusiveData.h
    MiCEquipModelProcInfo.cpp
    MiCEquipModelProcInfo.h
    MiCEquipModelData.cpp
    MiCEquipModelData.h
    MiGachaData.cpp
    MiGachaData.h
    MiCGuardianAssistData.cpp
    MiCGuardianAssistData.h
    MiCGuideData.cpp
    MiCGuideData.h
    MiGuideArrowData.cpp
    MiGuideArrowData.h
    MiChanceItemData.cpp
    MiChanceItemData.h
    MiCHelpData.cpp
    MiCHelpData.h
    MiCHouraiData.cpp
    MiCHouraiData.h
    MiCHouraiMessageData.h
    MiCHouraiMessageData.cpp
    MiCItemBaseData.cpp
    MiCItemBaseData.h
    MiCItemData.cpp
    MiCItemData.h
    MiCItemMotionData.cpp
    MiCItemMotionData.h
    MiCItemSPEffectData.cpp
    MiCItemSPEffectData.h
    MiKeyItemData.h
    MiKeyItemData.cpp
    MiKeyItemSortData.h
    MiKeyItemSortData.cpp
    MiCKeyItemData.h
    MiCKeyItemData.cpp
    MiCLoadingCommercialData.h
    MiCLoadingCommercialData.cpp
    MiFacilityData.h
    MiFacilityData.cpp
    MiZoneChangeData.h
    MiZoneChangeData.cpp
    MiCMapData.h
    MiCMapData.cpp
    MiMultiTalkCmdTbl.cpp
    MiMultiTalkCmdTbl.h
    MiCMultiTalkData.cpp
    MiCMultiTalkData.h
    MiCMultiTalkDirectionData.h
    MiCMultiTalkDirectionData.cpp
    MiCMultiTalkPopData.h
    MiCMultiTalkPopData.cpp
    MiMultiTalkPopCameraTbl.h
    MiMultiTalkPopCameraTbl.cpp
    MiMultiTalkPopCharaTbl.h
    MiMultiTalkPopCharaTbl.cpp
    MiCMessageData.cpp
    MiCMessageData.h
    MiCNakamaQuestRewardData.cpp
    MiCNakamaQuestRewardData.h
    MiNakamaQuestRewardFixedData.cpp
    MiNakamaQuestRewardFixedData.h
    MiNakamaQuestRewardVariableTbl.cpp
    MiNakamaQuestRewardVariableTbl.h
    MiCPolygonMovieData.cpp
    MiCPolygonMovieData.h
    MiCSkillBase.cpp
    MiCSkillBase.h
    MiCSkillCast.cpp
    MiCSkillCast.h
    MiCSkillShoot.cpp
    MiCSkillShoot.h
    MiCSkillBullet.cpp
    MiCSkillBullet.h
    MiCSkillTarget.cpp
    MiCSkillTarget.h
    MiCSkillHit.cpp
    MiCSkillHit.h
    MiCSkillEquipCategory.cpp
    MiCSkillEquipCategory.h
    MiCSkillData.cpp
    MiCSkillData.h
    MiCSpecialSkillEffectData.cpp
    MiCSpecialSkillEffectData.h
    MiCStatusData.cpp
    MiCStatusData.h
    MiCTimeAttackData.cpp
    MiCTimeAttackData.h
    MiCTitleData.cpp
    MiCTitleData.h
    MiCTransformedModelEntry.cpp
    MiCTransformedModelEntry.h
    MiCTransformedModelData.cpp
    MiCTransformedModelData.h
    MiCValuableData.cpp
    MiCValuableData.h
    MiCValuablesData.cpp
    MiCValuablesData.h
    MiCultureItemData.cpp
    MiCultureItemData.h
    MiCUraFieldData.cpp
    MiCUraFieldData.h
    MiCZoneRelationData.cpp
    MiCZoneRelationData.h
    MiRelationZoneIDData.cpp
    MiRelationZoneIDData.h
    MiPMBaseInfo.cpp
    MiPMBaseInfo.h
    MiPMCameraKeyTbl.cpp
    MiPMCameraKeyTbl.h
    MiPMMsgKeyTbl.cpp
    MiPMMsgKeyTbl.h
    MiPMBGMKeyTbl.cpp
    MiPMBGMKeyTbl.h
    MiPMSEKeyTbl.cpp
    MiPMSEKeyTbl.h
    MiPMEffectKeyTbl.cpp
    MiPMEffectKeyTbl.h
    MiPMFadeKeyTbl.cpp
    MiPMFadeKeyTbl.h
    MiPMGouraudKeyTbl.cpp
    MiPMGouraudKeyTbl.h
    MiPMFogKeyTbl.cpp
    MiPMFogKeyTbl.h
    MiPMScalingHelperTbl.cpp
    MiPMScalingHelperTbl.h
    MiPMAttachCharacterTbl.cpp
    MiPMAttachCharacterTbl.h
    MiPMMotionKeyTbl.cpp
    MiPMMotionKeyTbl.h
    MiConditionData.cpp
    MiConditionData.h
    MiCorrectTbl.h
    MiCorrectTbl.cpp
    MiCostTbl.cpp
    MiCostTbl.h
    MiCQuestData.cpp
    MiCQuestData.h
    MiDamageData.cpp
    MiDamageData.h
    MiDCategoryData.cpp
    MiDCategoryData.h
    MiDevilBattleData.cpp
    MiDevilBattleData.h
    MiDeunionItemCatalystData.cpp
    MiDeunionItemCatalystData.h
    MiDevilBookBonusData.cpp
    MiDevilBookBonusData.h
    MiDevilBookBonusMitamaData.cpp
    MiDevilBookBonusMitamaData.h
    MiDevilBookData.cpp
    MiDevilBookData.h
    MiDevilBoostData.cpp
    MiDevilBoostData.h
    MiDevilBoostExtraData.cpp
    MiDevilBoostExtraData.h
    MiDevilBoostItemData.cpp
    MiDevilBoostItemData.h
    MiDevilBoostLotData.cpp
    MiDevilBoostLotData.h
    MiDevilBoostRequirementData.cpp
    MiDevilBoostRequirementData.h
    MiDevilBoostResultData.cpp
    MiDevilBoostResultData.h
    MiDevilCrystalData.h
    MiDevilCrystalData.cpp
    MiDevilData.h
    MiDevilData.cpp
    MiDevilEquipmentData.h
    MiDevilEquipmentData.cpp
    MiDevilEquipmentItemData.h
    MiDevilEquipmentItemData.cpp
    MiDevilFamiliarityData.cpp
    MiDevilFamiliarityData.h
    MiDevilFusionData.h
    MiDevilFusionData.cpp
    MiDevilLVUpData.cpp
    MiDevilLVUpData.h
    MiDevilLVUpRateData.cpp
    MiDevilLVUpRateData.h
    MiDevilReunionConditionData.cpp
    MiDevilReunionConditionData.h
    MiDisassemblyData.cpp
    MiDisassemblyData.h
    MiDisassemblyMaterialData.cpp
    MiDisassemblyMaterialData.h
    MiDisassemblyTriggerData.cpp
    MiDisassemblyTriggerData.h
    MiDischargeData.cpp
    MiDischargeData.h
    MiDoTDamageData.cpp
    MiDoTDamageData.h
    MiDynamicMapData.h
    MiDynamicMapData.cpp
    MiEffectData.cpp
    MiEffectData.h
    MiEffectiveRangeData.cpp
    MiEffectiveRangeData.h
    MiEnchantCharasticData.h
    MiEnchantCharasticData.cpp
    MiEnchantData.h
    MiEnchantData.cpp
    MiEnchantInitializeData.cpp
    MiEnchantInitializeData.h
    MiEnchantPiercingData.cpp
    MiEnchantPiercingData.h
    EnchantSetData.h
    EnchantSetData.cpp
    EnchantSpecialData.h
    EnchantSpecialData.cpp
    MiEquipmentSetData.cpp
    MiEquipmentSetData.h
    MiExchangeData.cpp
    MiExchangeData.h
    MiExchangeObjectData.cpp
    MiExchangeObjectData.h
    MiExchangeOptionData.cpp
    MiExchangeOptionData.h
    MiExpertChainData.cpp
    MiExpertChainData.h
    MiExpertClassData.cpp
    MiExpertClassData.h
    MiExpertData.cpp
    MiExpertData.h
    MiExpertGrowthTbl.cpp
    MiExpertGrowthTbl.h
    MiExpertRankData.cpp
    MiExpertRankData.h
    MiExpertTitleData.cpp
    MiExpertTitleData.h
    MiFindInfo.cpp
    MiFindInfo.h
    MiGrowthData.cpp
    MiGrowthData.h
    MiGuardianAssistData.cpp
    MiGuardianAssistData.h
    MiGuardianLevelData.cpp
    MiGuardianLevelData.h
    MiGuardianLevelDataEntry.cpp
    MiGuardianLevelDataEntry.h
    MiGuardianSpecialData.cpp
    MiGuardianSpecialData.h
    MiGuardianUnlockData.cpp
    MiGuardianUnlockData.h
    MiGvGArrayData.cpp
    MiGvGArrayData.h
    MiGvGData.cpp
    MiGvGData.h
    MiGvGTrophyData.cpp
    MiGvGTrophyData.h
    MiHNPCAppearanceData.cpp
    MiHNPCAppearanceData.h
    MiHNPCBasicData.cpp
    MiHNPCBasicData.h
    MiHNPCData.cpp
    MiHNPCData.h
    MiItemBasicData.h
    MiItemBasicData.cpp
    MiItemPvPData.h
    MiItemPvPData.cpp
    MiKnockBackData.cpp
    MiKnockBackData.h
    MiMissionData.h
    MiMissionData.cpp
    MiMissionExit.h
    MiMissionExit.cpp
    MiMitamaReunionBonusData.cpp
    MiMitamaReunionBonusData.h
    MiMitamaReunionSetBonusData.cpp
    MiMitamaReunionSetBonusData.h
    MiMitamaUnionBonusData.cpp
    MiMitamaUnionBonusData.h
    MiModificationCatalystData.cpp
    MiModificationCatalystData.h
    MiModificationData.cpp
    MiModificationData.h
    MiModificationExtCatalystData.cpp
    MiModificationExtCatalystData.h
    MiModificationExtEffectData.cpp
    MiModificationExtEffectData.h
    MiModificationExtRecipeData.cpp
    MiModificationExtRecipeData.h
    MiModificationTriggerData.cpp
    MiModificationTriggerData.h
    MiModifiedEffectData.cpp
    MiModifiedEffectData.h
    MiNegotiationDamageData.cpp
    MiNegotiationDamageData.h
    MiNegotiationData.cpp
    MiNegotiationData.h
    MiNextEpisodeInfo.cpp
    MiNextEpisodeInfo.h
    MiNPCBarterData.cpp
    MiNPCBarterData.h
    MiNPCBarterConditionDataEntry.h
    MiNPCBarterConditionDataEntry.cpp
    MiNPCBarterConditionData.h
    MiNPCBarterConditionData.cpp
    MiNPCBarterGroupEntry.h
    MiNPCBarterGroupEntry.cpp
    MiNPCBarterGroupData.h
    MiNPCBarterGroupData.cpp
    MiNPCBarterItemData.cpp
    MiNPCBarterItemData.h
    MiNPCBarterTextData.h
    MiNPCBarterTextData.cpp
    MiNPCBasicData.cpp
    MiNPCBasicData.h
    MiNPCInvisibleDataEntry.cpp
    MiNPCInvisibleDataEntry.h
    MiNPCInvisibleData.cpp
    MiNPCInvisibleData.h
    MiONPCData.cpp
    MiONPCData.h
    MiPCData.cpp
    MiPCData.h
    MiUnionTbl.cpp
    MiUnionTbl.h
    MiPCBattleData.cpp
    MiPCBattleData.h
    MiPCBasicData.cpp
    MiPCBasicData.h
    MiAppearanceData.cpp
    MiAppearanceData.h
    MiPossessionData.h
    MiPossessionData.cpp
    MiQuestBonusData.h
    MiQuestBonusData.cpp
    MiQuestBonusCodeData.h
    MiQuestBonusCodeData.cpp
    MiQuestData.h
    MiQuestData.cpp
    MiQuestPhaseData.h
    MiQuestPhaseData.cpp
    QuestPhaseRequirement.h
    QuestPhaseRequirement.cpp
    MiQuestUpperCondition.h
    MiQuestUpperCondition.cpp
    MiRentalData.h
    MiRentalData.cpp
    MiReportTypeData.h
    MiReportTypeData.cpp
    MiRestrictionData.cpp
    MiRestrictionData.h
    MiShopProductData.cpp
    MiShopProductData.h
    MiSItemData.h
    MiSItemData.cpp
    MiSkillBasicData.cpp
    MiSkillBasicData.h
    MiSkillCharasticData.cpp
    MiSkillCharasticData.h
    MiSkillData.cpp
    MiSkillData.h
    MiSkillItemStatusCommonData.h
    MiSkillItemStatusCommonData.cpp
    MiSkillPvPData.cpp
    MiSkillPvPData.h
    MiSkillSpecialParams.cpp
    MiSkillSpecialParams.h
    MiSkillTbl.h
    MiSkillTbl.cpp
    MiSlotInitializeData.cpp
    MiSlotInitializeData.h
    MiSlotPiercingData.cpp
    MiSlotPiercingData.h
    MiSpecialConditionData.h
    MiSpecialConditionData.cpp
    MiSStatusData.cpp
    MiSStatusData.h
    MiStatusBasicData.cpp
    MiStatusBasicData.h
    MiStatusData.cpp
    MiStatusData.h
    MiSummonData.cpp
    MiSummonData.h
    MiSynthesisData.cpp
    MiSynthesisData.h
    MiSynthesisItemData.cpp
    MiSynthesisItemData.h
    MiCSynthesisCatalystData.cpp
    MiCSynthesisCatalystData.h
    MiCTalkMessageData.cpp
    MiCTalkMessageData.h
    MiTankData.h
    MiTankData.cpp
    MiTargetData.cpp
    MiTargetData.h
    MiTimeLimitData.h
    MiTimeLimitData.cpp
    MiTitleData.h
    MiTitleData.cpp
    MiTriUnionKreuzItemData.cpp
    MiTriUnionKreuzItemData.h
    MiTriUnionSpecialData.cpp
    MiTriUnionSpecialData.h
    MiUIInfoData.h
    MiUIInfoData.cpp
    MiUnionData.cpp
    MiUnionData.h
    MiUnionItemsHelperData.cpp
    MiUnionItemsHelperData.h
    MiUraFieldTowerData.cpp
    MiUraFieldTowerData.h
    MiUseRestrictionsData.cpp
    MiUseRestrictionsData.h
    MiUltimateBattleBaseData.cpp
    MiUltimateBattleBaseData.h
    MiSpotData.cpp
    MiSpotData.h
    MiWarpPointData.cpp
    MiWarpPointData.h
    MiWorldData.cpp
    MiWorldData.h
    MiCreateAreaIdTbl.cpp
    MiCreateAreaIdTbl.h
    MiChannelTbl.cpp
    MiChannelTbl.h
    MiZoneBasicData.h
    MiZoneBasicData.cpp
    MiZoneBGMData.h
    MiZoneBGMData.cpp
    MiZoneCameraData.h
    MiZoneCameraData.cpp
    MiZoneFileData.h
    MiZoneFileData.cpp
    MiZoneFogData.h
    MiZoneFogData.cpp
    MiZoneGouraudData.h
    MiZoneGouraudData.cpp
    MiZoneLensFlareLayerData.h
    MiZoneLensFlareLayerData.cpp
    MiZoneLensFlareData.h
    MiZoneLensFlareData.cpp
    MiZoneOtherData.h
    MiZoneOtherData.cpp
    MiZoneSkyData.h
    MiZoneSkyData.cpp
    MiZoneData.h
    MiZoneData.cpp
    MiCModifiedEffectData.h
    MiCModifiedEffectData.cpp
    MiCModelData.h
    MiCModelData.cpp
    MiCModelBase.h
    MiCModelBase.cpp
    MiCModelView.h
    MiCModelView.cpp
    MiCModelMotionMap.h
    MiCModelMotionMap.cpp
    MiCIconData.h
    MiCIconData.cpp
    MiItemData.h
    MiItemData.cpp
    MiCSoundData.h
    MiCSoundData.cpp
    MiEventDirectionData.h
    MiEventDirectionData.cpp

    # BinaryData schema
    MiActionLogicData.xsd
    MiAIData.xsd
    MiAutoLiveData.xsd
    MiBazaarClerkNPCData.xsd
    MiBlendData.xsd
    MiBlendExtData.xsd
    MiCAppearanceEquipData.xsd
    MiCBlockNameData.xsd
    MiCChanceItemData.xsd
    MiCCultureData.xsd
    MiCDevilBookBonusData.xsd
    MiCDevilBookBonusMitamaData.xsd
    MiCDevilBoostIconData.xsd
    MiCDevilDungeonData.xsd
    MiCDevilEquipmentExclusiveData.xsd
    MiCEquipModelData.xsd
    MiCEventData.xsd
    MiCEventMessageData.xsd
    MiCGuardianAssistData.xsd
    MiCGuideData.xsd
    MiChanceItemData.xsd
    MiCHelpData.xsd
    MiCHouraiData.xsd
    MiCHouraiMessageData.xsd
    MiCIconData.xsd
    MiCItemData.xsd
    MiCKeyItemData.xsd
    MiCLoadingCommercialData.xsd
    MiCMapData.xsd
    MiCMessageData.xsd
    MiCModelData.xsd
    MiCModifiedEffectData.xsd
    MiCMultiTalkData.xsd
    MiCMultiTalkDirectionData.xsd
    MiCMultiTalkPopData.xsd
    MiCNakamaQuestRewardData.xsd
    MiCPolygonMovieData.xsd
    MiCQuestData.xsd
    MiCSkillData.xsd
    MiCSoundData.xsd
    MiCSpecialSkillEffectData.xsd
    MiCStatusData.xsd
    MiCSynthesisCatalystData.xsd
    MiCTalkMessageData.xsd
    MiCTimeAttackData.xsd
    MiCTitleData.xsd
    MiCTransformedModelData.xsd
    MiCultureItemData.xsd
    MiCUraFieldData.xsd
    MiCValuableData.xsd
    MiCValuablesData.xsd
    MiCZoneRelationData.xsd
    MiDeunionItemCatalystData.xsd
    MiDevilBookBonusData.xsd
    MiDevilBookBonusMitamaData.xsd
    MiDevilBookData.xsd
    MiDevilBoostData.xsd
    MiDevilBoostExtraData.xsd
    MiDevilBoostItemData.xsd
    MiDevilBoostLotData.xsd
    MiDevilData.xsd
    MiDevilEquipmentData.xsd
    MiDevilEquipmentItemData.xsd
    MiDevilFusionData.xsd
    MiDevilLVUpRateData.xsd
    MiDisassemblyData.xsd
    MiDisassemblyTriggerData.xsd
    MiDynamicMapData.xsd
    MiEnchantData.xsd
    MiEnchantInitializeData.xsd
    MiEnchantPiercingData.xsd
    MiEquipmentSetData.xsd
    MiEventDirectionData.xsd
    MiExchangeData.xsd
    MiExpertData.xsd
    MiExpertTitleData.xsd
    MiGachaData.xsd
    MiGuardianAssistData.xsd
    MiGuardianLevelData.xsd
    MiGuardianSpecialData.xsd
    MiGuardianUnlockData.xsd
    MiGvGData.xsd
    MiGvGTrophyData.xsd
    MiHNPCData.xsd
    MiItemData.xsd
    MiMissionData.xsd
    MiMitamaReunionBonusData.xsd
    MiMitamaReunionSetBonusData.xsd
    MiMitamaUnionBonusData.xsd
    MiModificationCatalystData.xsd
    MiModificationData.xsd
    MiModificationExtCatalystData.xsd
    MiModificationExtEffectData.xsd
    MiModificationExtRecipeData.xsd
    MiModificationTriggerData.xsd
    MiModifiedEffectData.xsd
    MiNPCBarterConditionData.xsd
    MiNPCBarterData.xsd
    MiNPCBarterGroupData.xsd
    MiNPCBarterTextData.xsd
    MiNPCInvisibleData.xsd
    MiONPCData.xsd
    MiPCData.xsd
    MiQuestBonusCodeData.xsd
    MiQuestBonusData.xsd
    MiQuestData.xsd
    MiReportTypeData.xsd
    MiShopProductData.xsd
    MiSItemData.xsd
    MiSkillData.xsd
    MiSlotInitializeData.xsd
    MiSlotPiercingData.xsd
    MiSpotData.xsd
    MiStatusData.xsd
    MiSynthesisData.xsd
    MiTankData.xsd
    MiTimeLimitData.xsd
    MiTitleData.xsd
    MiTriUnionKreuzItemData.xsd
    MiTriUnionSpecialData.xsd
    MiUIInfoData.xsd
    MiUltimateBattleBaseData.xsd
    MiUnionItemsHelperData.xsd
    MiUraFieldTowerData.xsd
    MiWarpPointData.xsd
    MiWorldData.xsd
    MiZoneData.xsd
)

COVERALLS_SOURCES(${${PROJECT_NAME}_SRCS})

ADD_LIBRARY(comp STATIC ${${PROJECT_NAME}_SRCS} ${${PROJECT_NAME}_HDRS}
    ${${PROJECT_NAME}_MOC_SRCS} ${${PROJECT_NAME}_STRUCTS})

IF(BUILD_EXOTIC)
    SET_SOURCE_FILES_LANGUAGE(${${PROJECT_NAME}_SRCS}
        ${${PROJECT_NAME}_MOC_SRCS} ${${PROJECT_NAME}_STRUCTS})

    TARGET_COMPILE_DEFINITIONS(comp PUBLIC
        "EXOTIC_HEADER=${EXOTIC_HEADER}"
        "EXOTIC_RANDOM_FUNC=${EXOTIC_RANDOM_FUNC}"
    )
ENDIF(BUILD_EXOTIC)

TARGET_COMPILE_DEFINITIONS(comp PUBLIC ${SQRAT_DEFINES})

IF(USE_MBED_TLS)
    TARGET_COMPILE_DEFINITIONS(comp PUBLIC USE_MBED_TLS=1)
ENDIF(USE_MBED_TLS)

SET_TARGET_PROPERTIES(comp PROPERTIES FOLDER "Libraries")

IF(SYSTEMD_FOUND)
    SET(SYSTEMD_INCLUDES ${SYSTEMD_INCLUDE_DIRS})
ENDIF(SYSTEMD_FOUND)

TARGET_INCLUDE_DIRECTORIES(comp PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBCOMP_INCLUDES}
    ${ASIO_INCLUDE_DIRS}
    ${SYSTEMD_INCLUDES}
    ${SQRAT_INCLUDE_DIRS}
)

IF(SYSTEMD_FOUND)
    SET(SYSTEMD_LIBS ${SYSTEMD_LIBRARIES})
ENDIF(SYSTEMD_FOUND)

IF(BUILD_EXOTIC)
    SET(OBJGEN_LIB objgen_exotic)
ELSE(BUILD_EXOTIC)
    SET(OBJGEN_LIB objgen)
ENDIF(BUILD_EXOTIC)

IF(BUILD_EXOTIC)
    IF(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(comp ${LIBOBJECTS_LIB} exotic_mbedcrypto
            ${SYSTEM_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
            ${OBJGEN_LIB} exotic_tinyxml2 physfs ${EXOTIC_ZLIB_LIBRARIES}
        )
    ELSE(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(comp ${LIBOBJECTS_LIB} ${EXOTIC_OPENSSL_LIBRARIES}
            ${SYSTEM_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
            ${OBJGEN_LIB} exotic_tinyxml2 physfs ${EXOTIC_ZLIB_LIBRARIES})
    ENDIF(USE_MBED_TLS)
ELSE(BUILD_EXOTIC)
    IF(USE_MBED_TLS)
        # We still need to link to OpenSSL for the MariaDB library
        TARGET_LINK_LIBRARIES(comp ${LIBOBJECTS_LIB} mariadbclient mbedcrypto
            ${OPENSSL_LIBRARIES} ${SYSTEM_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
            ${OBJGEN_LIB} sqlite3 squirrel sqstdlib ttvfs ttvfs_zip tinyxml2
            physfs ${ZLIB_LIBRARIES} ${SYSTEMD_LIBS})
    ELSE(USE_MBED_TLS)
        TARGET_LINK_LIBRARIES(comp ${LIBOBJECTS_LIB} mariadbclient
            ${OPENSSL_LIBRARIES} ${SYSTEM_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}
            ${OBJGEN_LIB} sqlite3 squirrel sqstdlib ttvfs ttvfs_zip tinyxml2
            physfs ${ZLIB_LIBRARIES} ${SYSTEMD_LIBS})
    ENDIF(USE_MBED_TLS)
ENDIF(BUILD_EXOTIC)

IF(NOT BUILD_EXOTIC)
    ADD_DEPENDENCIES(comp asio gsl)
ENDIF(NOT BUILD_EXOTIC)

IF(WIN32)
    TARGET_LINK_LIBRARIES(comp shlwapi advapi32 iphlpapi psapi shell32
        userenv ws2_32 dbghelp)
ENDIF(WIN32)

IF(USE_COTIRE)
    cotire(comp)
ENDIF(USE_COTIRE)

IF(NOT BUILD_EXOTIC)
    # List of unit tests to add to CTest.
    SET(${PROJECT_NAME}_TEST_SRCS
        Convert
        Crypto

        # This test can take too long so disable it for now.
        DiffieHellman

        GeneratedObjects
        MariaDB
        Packet
        ScriptEngine
        String
        VectorStream
        #XmlUtils
    )

    IF(NOT BSD)
        # Add the unit tests.
        CREATE_GTESTS(LIBS ${LIBOBJECTS_LIB} comp
            SRCS ${${PROJECT_NAME}_TEST_SRCS})
    ENDIF(NOT BSD)

    IF(LIBCOMP_STANDALONE)
        INSTALL(TARGETS comp DESTINATION lib)
        INSTALL(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/objgen/"
            DESTINATION include PATTERN *.h)
        INSTALL(DIRECTORY "${CMAKE_BINARY_DIR}/api/"
            DESTINATION api)

        # Include the PDB file if on Windows
        IF(WIN32)
            INSTALL(FILES ${CMAKE_BINARY_DIR}/bin/$<CONFIG>/comp.pdb DESTINATION lib)
        ENDIF(WIN32)
    ENDIF(LIBCOMP_STANDALONE)
ENDIF(NOT BUILD_EXOTIC)
