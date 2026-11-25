// TL constructor tables (current schema, layer 225) for the subset of the
// Telegram API this app uses. Ids verified against core.telegram.org.

import { def, F, vec, obj, buildAny } from "./tlengine";

// ---------- MTProto service ----------
def("RpcResult", "rpc_result", 0xf35c6d01, [F("req_msg_id", "long"), F("result", obj("Object"))]);
def("RpcError", "rpc_error", 0x2144ca19, [F("error_code", "int"), F("error_message", "string")]);
def("MsgContainer", "msg_container", 0x73f1f8dc, [F("messages", vec(obj("ContainerMessage")))]);
def("ContainerMessage", "message", 0, [F("msg_id", "long"), F("seqno", "int"), F("bytes", "int"), F("body", obj("Object"))]);
def("MsgsAck", "msgs_ack", 0x62d6b459, [F("msg_ids", vec("long"))]);
def("GzipPacked", "gzip_packed", 0x3072cfa1, [F("packed_data", "bytes")]);
def("NewSessionCreated", "new_session_created", 0x9ec20908, [F("first_msg_id", "long"), F("unique_id", "long"), F("server_salt", "long")]);
def("BadServerSalt", "bad_server_salt", 0xedab447b, [F("bad_msg_id", "long"), F("bad_msg_seqno", "int"), F("error_code", "int"), F("new_server_salt", "long")]);
def("Pong", "pong", 0x347773c5, [F("msg_id", "long"), F("ping_id", "long")]);

// ---------- handshake ----------
def("Handshake", "req_pq_multi", 0xbe7e8ef1, [F("nonce", "int128")]);
def("Handshake", "resPQ", 0x05162463, [F("nonce", "int128"), F("server_nonce", "int128"), F("pq", "bytes"), F("fingerprints", vec("long"))]);
def("Handshake", "p_q_inner_data_dc", 0xa9f55f95, [F("pq", "bytes"), F("p", "bytes"), F("q", "bytes"), F("nonce", "int128"), F("server_nonce", "int128"), F("new_nonce", "int256"), F("dc", "int")]);
def("Handshake", "req_DH_params", 0xd712e4be, [F("nonce", "int128"), F("server_nonce", "int128"), F("p", "bytes"), F("q", "bytes"), F("public_key_fingerprint", "long"), F("encrypted_data", "bytes")]);
def("Handshake", "server_DH_params_ok", 0xd0e8075c, [F("nonce", "int128"), F("server_nonce", "int128"), F("encrypted_answer", "bytes")]);
def("Handshake", "server_DH_inner_data", 0xb5890dba, [F("nonce", "int128"), F("server_nonce", "int128"), F("g", "int"), F("dh_prime", "bytes"), F("g_a", "bytes"), F("server_time", "int")]);
def("Handshake", "set_client_DH_params", 0xf5045f1f, [F("nonce", "int128"), F("server_nonce", "int128"), F("encrypted_data", "bytes")]);
def("Handshake", "client_DH_inner_data", 0x6643b654, [F("nonce", "int128"), F("server_nonce", "int128"), F("retry_id", "long"), F("g_b", "bytes")]);
def("Handshake", "dh_gen_ok", 0x3bcbf734, [F("nonce", "int128"), F("server_nonce", "int128"), F("new_nonce_hash1", "int128")]);
def("Handshake", "dh_gen_retry", 0x46dc1fb9, [F("nonce", "int128"), F("server_nonce", "int128"), F("new_nonce_hash2", "int128")]);
def("Handshake", "dh_gen_fail", 0xa69dae02, [F("nonce", "int128"), F("server_nonce", "int128"), F("new_nonce_hash3", "int128")]);

// ---------- wrapping ----------
def("Wrapper", "invokeWithLayer", 0xda9b0d0d, [F("layer", "int"), F("query", obj("Object"))]);
def("Wrapper", "initConnection", 0xc1cd5ea9, [
  F("flags", "int"),
  F("api_id", "int"),
  F("device_model", "string"),
  F("system_version", "string"),
  F("app_version", "string"),
  F("system_lang_code", "string"),
  F("lang_pack", "string"),
  F("lang_code", "string"),
]);

// ---------- auth ----------
def("CodeSettings", "codeSettings", 0xad253d78, [F("flags", "int")]);
def("Method", "auth.sendCode", 0xa677244f, [F("phone_number", "string"), F("api_id", "int"), F("api_hash", "string"), F("settings", obj("CodeSettings"))]);
def("AuthSentCode", "auth.sentCode", 0x5e002502, [F("flags", "int"), F("type", obj("SentCodeType")), F("phone_code_hash", "string"), F("next_type", obj("CodeType"), 1), F("timeout", "int", 2)]);
def("SentCodeType", "auth.sentCodeTypeApp", 0x3dbb5986, [F("length", "int")]);
def("SentCodeType", "auth.sentCodeTypeSms", 0xc000bba2, [F("length", "int")]);
def("SentCodeType", "auth.sentCodeTypeCall", 0x5353e5a7, [F("length", "int")]);
def("SentCodeType", "auth.sentCodeTypeFlashCall", 0xab03c6d9, [F("pattern", "string")]);
def("SentCodeType", "auth.sentCodeTypeMissedCall", 0x82006484, [F("prefix", "string"), F("length", "int")]);
def("SentCodeType", "auth.sentCodeTypeFragmentSms", 0xd9565c39, [F("url", "string"), F("length", "int")]);
def("CodeType", "auth.codeTypeSms", 0x72a3158c, []);
def("CodeType", "auth.codeTypeCall", 0x741cd3e3, []);
def("CodeType", "auth.codeTypeFlashCall", 0x226ccefb, []);
def("CodeType", "auth.codeTypeMissedCall", 0xd61ad6ee, []);
def("CodeType", "auth.codeTypeFragmentSms", 0x06ed998c, []);
def("Method", "auth.signIn", 0x8d52a951, [F("flags", "int"), F("phone_number", "string"), F("phone_code_hash", "string"), F("phone_code", "string", 0)]);
def("AuthAuthorization", "auth.authorization", 0x2ea2c0d4, [F("flags", "int"), F("user", obj("User"))]);
def("Method", "account.getPassword", 0x548a30f5, []);
def("AccountPassword", "account.password", 0x957b50fb, [F("flags", "int"), F("current_algo", obj("PasswordKdfAlgo"), 2), F("srp_B", "bytes", 2), F("srp_id", "long", 2), F("secure_random", "bytes")]);
def("PasswordKdfAlgo", "passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow", 0x3a912d4a, [F("salt1", "bytes"), F("salt2", "bytes"), F("g", "int"), F("p", "bytes")]);
def("InputCheckPasswordSRP", "inputCheckPasswordSRP", 0xd27ff082, [F("srp_id", "long"), F("A", "bytes"), F("M1", "bytes")]);
def("Method", "auth.checkPassword", 0xd18b4d16, [F("password", obj("InputCheckPasswordSRP"))]);
def("Method", "auth.logOut", 0x3e72ba19, []);
def("AuthLoggedOut", "auth.loggedOut", 0xc3a2835f, [F("flags", "int")]);

// ---------- peers ----------
def("Peer", "peerUser", 0x59511722, [F("user_id", "long")]);
def("Peer", "peerChat", 0x36c6019a, [F("chat_id", "long")]);
def("Peer", "peerChannel", 0xa2a5371e, [F("channel_id", "long")]);
def("InputPeer", "inputPeerEmpty", 0x7f3b18ea, []);
def("InputPeer", "inputPeerSelf", 0x7da07ec9, []);
def("InputPeer", "inputPeerChat", 0x35a95cb9, [F("chat_id", "long")]);
def("InputPeer", "inputPeerUser", 0xdde8a54c, [F("user_id", "long"), F("access_hash", "long")]);
def("InputPeer", "inputPeerChannel", 0x27bcbbfc, [F("channel_id", "long"), F("access_hash", "long")]);
def("InputUser", "inputUserEmpty", 0xb98886cf, []);
def("InputUser", "inputUserSelf", 0xf7c1b13f, []);
def("InputUser", "inputUser", 0xf21158c6, [F("user_id", "long"), F("access_hash", "long")]);
def("InputChannel", "inputChannelEmpty", 0xee8c1e86, []);
def("InputChannel", "inputChannel", 0xf35aec28, [F("channel_id", "long"), F("access_hash", "long")]);
def("InputMessage", "inputMessageID", 0xa676a322, [F("id", "int")]);

// ---------- users / chats ----------
def("UserProfilePhoto", "userProfilePhotoEmpty", 0x4f11bae1, []);
def("UserProfilePhoto", "userProfilePhoto", 0x82d1f706, [F("flags", "int"), F("photo_id", "long"), F("stripped_thumb", "bytes", 1), F("dc_id", "int")]);
def("UserStatus", "userStatusEmpty", 0x09d05049, []);
def("UserStatus", "userStatusOnline", 0xedb93949, [F("expires", "int")]);
def("UserStatus", "userStatusOffline", 0x8c703f, [F("was_online", "int")]);
def("UserStatus", "userStatusRecently", 0x7b197dc8, [F("flags", "int")]);
def("UserStatus", "userStatusLastWeek", 0x541a1d1a, [F("flags", "int")]);
def("UserStatus", "userStatusLastMonth", 0x65899777, [F("flags", "int")]);
def("RestrictionReason", "restrictionReason", 0xd072acb4, [F("platform", "string"), F("reason", "string"), F("text", "string")]);
def("Username", "username", 0xb4073647, [F("flags", "int"), F("username", "string")]);
def("RecentStory", "recentStory", 0x711d692d, [F("flags", "int"), F("max_id", "int", 1)]);
def("PeerColor", "peerColor", 0xb54b5acf, [F("flags", "int"), F("color", "int", 0), F("background_emoji_id", "long", 1)]);
def("EmojiStatus", "emojiStatusEmpty", 0x2de11aae, []);
def("EmojiStatus", "emojiStatus", 0xe7ff068a, [F("flags", "int"), F("document_id", "long"), F("until", "int", 0)]);
def("User", "userEmpty", 0xd3bc4b7a, [F("id", "long")]);
def("User", "user", 0x31774388, [
  F("flags", "int"),
  F("flags2", "int"),
  F("id", "long"),
  F("access_hash", "long", 0),
  F("first_name", "string", 1),
  F("last_name", "string", 2),
  F("username", "string", 3),
  F("phone", "string", 4),
  F("photo", obj("UserProfilePhoto"), 5),
  F("status", obj("UserStatus"), 6),
  F("restriction_reason", vec(obj("RestrictionReason")), 18),
  F("lang_code", "string", 22),
  F("emoji_status", obj("EmojiStatus"), 30),
  F("usernames", vec(obj("Username")), 0, true),
  F("stories_max_id", obj("RecentStory"), 5, true),
  F("color", obj("PeerColor"), 8, true),
  F("profile_color", obj("PeerColor"), 9, true),
]);
def("ChatPhoto", "chatPhotoEmpty", 0x37c1011c, []);
def("ChatPhoto", "chatPhoto", 0x1c6e1c11, [F("flags", "int"), F("photo_id", "long"), F("stripped_thumb", "bytes", 1), F("dc_id", "int")]);
def("ChatAdminRights", "chatAdminRights", 0x5fb224d5, [
  F("flags", "int"),
  F("change_info", "true", 0),
  F("post_messages", "true", 1),
  F("edit_messages", "true", 2),
  F("delete_messages", "true", 3),
  F("ban_users", "true", 4),
  F("invite_users", "true", 5),
  F("pin_messages", "true", 7),
  F("add_admins", "true", 9),
  F("anonymous", "true", 10),
  F("manage_call", "true", 11),
  F("other", "true", 12),
]);
def("ChatBannedRights", "chatBannedRights", 0x9f120418, [
  F("flags", "int"),
  F("view_messages", "true", 0),
  F("send_messages", "true", 1),
  F("send_media", "true", 2),
  F("invite_users", "true", 15),
  F("pin_messages", "true", 17),
  F("until_date", "int"),
]);
def("Chat", "chatEmpty", 0x29562865, [F("id", "long")]);
def("Chat", "chat", 0x41cbf256, [
  F("flags", "int"),
  F("id", "long"),
  F("title", "string"),
  F("photo", obj("ChatPhoto")),
  F("participants_count", "int"),
  F("date", "int"),
  F("version", "int"),
  F("admin_rights", obj("ChatAdminRights"), 14),
  F("default_banned_rights", obj("ChatBannedRights"), 18),
]);
def("Chat", "chatForbidden", 0x6592a1a7, [F("id", "long"), F("title", "string")]);
def("Chat", "channel", 0x1c32b11c, [
  F("flags", "int"),
  F("flags2", "int"),
  F("id", "long"),
  F("access_hash", "long", 13),
  F("title", "string"),
  F("username", "string", 6),
  F("photo", obj("ChatPhoto")),
  F("date", "int"),
  F("restriction_reason", vec(obj("RestrictionReason")), 9),
  F("admin_rights", obj("ChatAdminRights"), 14),
  F("banned_rights", obj("ChatBannedRights"), 15),
  F("default_banned_rights", obj("ChatBannedRights"), 18),
  F("participants_count", "int", 17),
  F("usernames", vec(obj("Username")), 0, true),
  F("stories_max_id", obj("RecentStory"), 4, true),
  F("color", obj("PeerColor"), 7, true),
  F("profile_color", obj("PeerColor"), 8, true),
  F("emoji_status", obj("EmojiStatus"), 9, true),
  F("level", "int", 10, true),
  F("subscription_until_date", "int", 11, true),
  F("bot_verification_icon", "long", 13, true),
  F("send_paid_messages_stars", "long", 14, true),
  F("linked_monoforum_id", "long", 18, true),
]);
def("Chat", "channelForbidden", 0x17d493d5, [F("flags", "int"), F("id", "long"), F("access_hash", "long"), F("title", "string"), F("until_date", "int", 16)]);
def("ChannelParticipant", "channelParticipant", 0x1bd54456, [F("flags", "int"), F("user_id", "long"), F("date", "int"), F("subscription_until_date", "int", 0), F("rank", "string", 2)]);
def("ChannelParticipant", "channelParticipantSelf", 0xa9478a1a, [F("flags", "int"), F("user_id", "long"), F("inviter_id", "long"), F("date", "int"), F("subscription_until_date", "int", 1), F("rank", "string", 2)]);
def("ChannelParticipant", "channelParticipantCreator", 0x2fe601d3, [F("flags", "int"), F("user_id", "long"), F("admin_rights", obj("ChatAdminRights")), F("rank", "string", 0)]);
def("ChannelParticipant", "channelParticipantAdmin", 0x34c3bb53, [F("flags", "int"), F("can_edit", "true", 0), F("self", "true", 1), F("user_id", "long"), F("inviter_id", "long", 1), F("promoted_by", "long"), F("date", "int"), F("admin_rights", obj("ChatAdminRights")), F("rank", "string", 2)]);
def("ChannelParticipant", "channelParticipantBanned", 0xd5f0ad91, [F("flags", "int"), F("left", "true", 0), F("peer", obj("Peer")), F("kicked_by", "long"), F("date", "int"), F("banned_rights", obj("ChatBannedRights")), F("rank", "string", 2)]);
def("ChannelParticipant", "channelParticipantLeft", 0x1b03f006, [F("peer", obj("Peer"))]);
def("ChannelParticipantsFilter", "channelParticipantsRecent", 0xde3f3c79, []);
def("ChannelParticipantsFilter", "channelParticipantsAdmins", 0xb4608969, []);

// ---------- messages ----------
def("MessagesChats", "messages.chats", 0x64ff9fd5, [F("chats", vec(obj("Chat")))]);
def("MessagesChats", "messages.chatsSlice", 0x9cd81144, [F("count", "int"), F("chats", vec(obj("Chat")))]);
def("ContactsResolvedPeer", "contacts.resolvedPeer", 0x7f077ad9, [F("peer", obj("Peer")), F("chats", vec(obj("Chat"))), F("users", vec(obj("User")))]);
def("ChannelsChannelParticipants", "channels.channelParticipants", 0x9ab0feaf, [F("count", "int"), F("participants", vec(obj("ChannelParticipant"))), F("chats", vec(obj("Chat"))), F("users", vec(obj("User")))]);
def("ChannelsChannelParticipants", "channels.channelParticipantsNotModified", 0xf0173fe9, []);

def("GeoPoint", "geoPointEmpty", 0x1117dd5f, []);
def("GeoPoint", "geoPoint", 0xb2a2f663, [F("flags", "int"), F("long", "double"), F("lat", "double"), F("access_hash", "long"), F("accuracy_radius", "int", 0)]);
def("FileLocation", "fileLocationUnavailable", 0x7c596b46, []);
def("FileLocation", "fileLocation", 0x53d69076, [F("volume_id", "long"), F("local_id", "int"), F("secret", "long"), F("dc_id", "int")]);
def("PhotoSize", "photoSizeEmpty", 0xe17e23c, [F("type", "string")]);
def("PhotoSize", "photoSize", 0x75c78e60, [F("type", "string"), F("w", "int"), F("h", "int"), F("size", "int")]);
def("PhotoSize", "photoCachedSize", 0x21e1ad6, [F("type", "string"), F("location", obj("FileLocation")), F("w", "int"), F("h", "int"), F("bytes", "bytes")]);
def("PhotoSize", "photoStrippedSize", 0xe0b0bc2e, [F("type", "string"), F("bytes", "bytes")]);
def("PhotoSize", "photoSizeProgressive", 0xfa3efb95, [F("type", "string"), F("w", "int"), F("h", "int"), F("sizes", vec("int"))]);
def("PhotoSize", "photoPathSize", 0xd8214d41, [F("type", "string"), F("bytes", "bytes")]);
def("InputStickerSet", "inputStickerSetEmpty", 0xffb62b95, []);
def("InputStickerSet", "inputStickerSetID", 0x9de7a269, [F("id", "long"), F("access_hash", "long")]);
def("InputStickerSet", "inputStickerSetShortName", 0x861cc8a0, [F("short_name", "string")]);
def("InputStickerSet", "inputStickerSetAnimatedEmoji", 0x28703c8, []);
def("InputStickerSet", "inputStickerSetDice", 0xe67f520e, [F("emoticon", "string")]);
def("InputStickerSet", "inputStickerSetAnimatedEmojiAnimations", 0xcde3739, []);
def("InputStickerSet", "inputStickerSetPremiumGifts", 0xc88b3b02, []);
def("InputStickerSet", "inputStickerSetEmojiGenericAnimations", 0x4c4d4ce, []);
def("InputStickerSet", "inputStickerSetEmojiDefaultStatuses", 0x29d0f5ee, []);
def("InputStickerSet", "inputStickerSetEmojiDefaultTopicIcons", 0x44c1f8e9, []);
def("InputStickerSet", "inputStickerSetEmojiChannelDefaultStatuses", 0x49748553, []);
def("InputStickerSet", "inputStickerSetTonGifts", 0x1cf671a0, []);
def("MaskCoords", "maskCoords", 0xaed6dbb2, [F("n", "int"), F("x", "double"), F("y", "double"), F("zoom", "double")]);
def("VideoSize", "videoSize", 0xde33b094, [F("flags", "int"), F("type", "string"), F("w", "int"), F("h", "int"), F("size", "int"), F("video_start_ts", "double", 0)]);
def("VideoSize", "videoSizeEmojiMarkup", 0xf85c413c, [F("emoji_id", "long"), F("background_colors", vec("int"))]);
def("VideoSize", "videoSizeStickerMarkup", 0xda082fe, [F("stickerset", obj("InputStickerSet")), F("sticker_id", "long"), F("background_colors", vec("int"))]);
def("DocumentAttribute", "documentAttributeImageSize", 0x6c37c15c, [F("w", "int"), F("h", "int")]);
def("DocumentAttribute", "documentAttributeAnimated", 0x11b58939, []);
def("DocumentAttribute", "documentAttributeSticker", 0x6319d612, [F("flags", "int"), F("alt", "string"), F("stickerset", obj("InputStickerSet")), F("mask_coords", obj("MaskCoords"), 0)]);
def("DocumentAttribute", "documentAttributeVideo", 0x43c57c48, [F("flags", "int"), F("duration", "double"), F("w", "int"), F("h", "int"), F("preload_prefix_size", "int", 2), F("video_start_ts", "double", 4), F("video_codec", "string", 5)]);
def("DocumentAttribute", "documentAttributeAudio", 0x9852f9c6, [F("flags", "int"), F("duration", "int"), F("title", "string", 0), F("performer", "string", 1), F("waveform", "bytes", 2)]);
def("DocumentAttribute", "documentAttributeFilename", 0x15590068, [F("file_name", "string")]);
def("DocumentAttribute", "documentAttributeHasStickers", 0x9801d2f7, []);
def("DocumentAttribute", "documentAttributeCustomEmoji", 0xfd149899, [F("flags", "int"), F("alt", "string"), F("stickerset", obj("InputStickerSet"))]);
def("Document", "documentEmpty", 0x36f8c871, [F("id", "long")]);
def("Document", "document", 0x8fd4c4d8, [
  F("flags", "int"),
  F("id", "long"),
  F("access_hash", "long"),
  F("file_reference", "bytes"),
  F("date", "int"),
  F("mime_type", "string"),
  F("size", "long"),
  F("thumbs", vec(obj("PhotoSize")), 0),
  F("video_thumbs", vec(obj("VideoSize")), 1),
  F("dc_id", "int"),
  F("attributes", vec(obj("DocumentAttribute"))),
]);
def("Photo", "photoEmpty", 0x2331b22d, [F("id", "long")]);
def("Photo", "photo", 0xfb197a65, [
  F("flags", "int"),
  F("id", "long"),
  F("access_hash", "long"),
  F("file_reference", "bytes"),
  F("date", "int"),
  F("sizes", vec(obj("PhotoSize"))),
  F("video_sizes", vec(obj("VideoSize")), 1),
  F("dc_id", "int"),
]);
def("MessageFwdHeader", "messageFwdHeader", 0x4e4df4bb, [
  F("flags", "int"),
  F("from_id", obj("Peer"), 0),
  F("from_name", "string", 5),
  F("date", "int"),
  F("channel_post", "int", 2),
  F("post_author", "string", 3),
  F("saved_from_peer", obj("Peer"), 4),
  F("saved_from_msg_id", "int", 4),
  F("saved_from_id", obj("Peer"), 8),
  F("saved_from_name", "string", 9),
  F("saved_date", "int", 10),
  F("psa_type", "string", 6),
]);
def("MessageEntity", "messageEntityUnknown", 0xbb92ba95, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityMention", 0xfa04579d, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityHashtag", 0x6f635b0d, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityBotCommand", 0x6cef8ac7, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityUrl", 0x6ed02538, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityEmail", 0x64e475c2, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityBold", 0xbd610bc9, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityItalic", 0x826f8b60, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityCode", 0x28a20571, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityPre", 0x73924be0, [F("offset", "int"), F("length", "int"), F("language", "string")]);
def("MessageEntity", "messageEntityTextUrl", 0x76a6d327, [F("offset", "int"), F("length", "int"), F("url", "string")]);
def("MessageEntity", "messageEntityMentionName", 0xdc7b1140, [F("offset", "int"), F("length", "int"), F("user_id", "long")]);
def("MessageEntity", "messageEntityPhone", 0x9b69e34b, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityCashtag", 0x4c4e743f, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityUnderline", 0x9c4e7e8b, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityStrike", 0xbf0693d4, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityBankCard", 0x761e6af4, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntitySpoiler", 0x32ca960f, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityCustomEmoji", 0xc8cf05f8, [F("offset", "int"), F("length", "int"), F("document_id", "long")]);
def("MessageEntity", "messageEntityBlockquote", 0xf1ccaaac, [F("flags", "int"), F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityFormattedDate", 0x904ac7c7, [F("flags", "int"), F("offset", "int"), F("length", "int"), F("date", "int")]);
def("MessageEntity", "messageEntityDiffInsert", 0x71777116, [F("offset", "int"), F("length", "int")]);
def("MessageEntity", "messageEntityDiffReplace", 0xc6c1e5a7, [F("offset", "int"), F("length", "int"), F("old_text", "string")]);
def("MessageEntity", "messageEntityDiffDelete", 0x652c1c5, [F("offset", "int"), F("length", "int")]);
def("MessageReplyHeader", "messageReplyHeader", 0x1b97dd66, [
  F("flags", "int"),
  F("reply_to_msg_id", "int", 4),
  F("reply_to_peer_id", obj("Peer"), 0),
  F("reply_from", obj("MessageFwdHeader"), 5),
  F("reply_media", obj("MessageMedia"), 8),
  F("reply_to_top_id", "int", 1),
  F("quote_text", "string", 6),
  F("quote_entities", vec(obj("MessageEntity")), 7),
  F("quote_offset", "int", 10),
]);
def("MessageReplyHeader", "messageReplyStoryHeader", 0xe5af939, [F("peer", obj("Peer")), F("story_id", "int")]);
def("MessageReplies", "messageReplies", 0x83d60fc2, [F("flags", "int"), F("replies", "int"), F("replies_pts", "int"), F("recent_repliers", vec(obj("Peer")), 1), F("channel_id", "long", 0), F("max_id", "int", 2), F("read_max_id", "int", 3)]);
def("Reaction", "reactionEmpty", 0x79f5d419, []);
def("Reaction", "reactionEmoji", 0x1b2286b8, [F("emoticon", "string")]);
def("Reaction", "reactionCustomEmoji", 0x8935fc73, [F("document_id", "long")]);
def("Reaction", "reactionPaid", 0x523da4eb, []);
def("ReactionCount", "reactionCount", 0xa3d1cb80, [F("flags", "int"), F("reaction", obj("Reaction")), F("count", "int")]);
def("MessagePeerReaction", "messagePeerReaction", 0x8c79b63c, [F("flags", "int"), F("peer_id", obj("Peer")), F("date", "int"), F("reaction", obj("Reaction"))]);
def("MessageReactor", "messageReactor", 0x4ba3a95a, [F("flags", "int"), F("peer_id", obj("Peer"), 3), F("count", "int")]);
def("MessageReactions", "messageReactions", 0xa339f0b, [F("flags", "int"), F("results", vec(obj("ReactionCount"))), F("recent_reactions", vec(obj("MessagePeerReaction")), 1), F("top_reactors", vec(obj("MessageReactor")), 4)]);
def("TextWithEntities", "textWithEntities", 0x751f3146, [F("text", "string"), F("entities", vec(obj("MessageEntity")))]);
def("FactCheck", "factCheck", 0xb89bfccf, [F("flags", "int"), F("country", "string", 1), F("text", obj("TextWithEntities"), 1), F("hash", "long")]);
def("StarsAmount", "starsAmount", 0xbbb6b4a3, [F("amount", "long"), F("nanos", "int")]);
def("SuggestedPost", "suggestedPost", 0xe8e37e5, [F("flags", "int"), F("price", obj("StarsAmount"), 3), F("schedule_date", "int", 0)]);
def("MessageMedia", "messageMediaEmpty", 0x3ded6320, []);
def("MessageMedia", "messageMediaPhoto", 0xe216eb63, [F("flags", "int"), F("photo", obj("Photo"), 0), F("ttl_seconds", "int", 2), F("video", obj("Document"), 4)]);
def("MessageMedia", "messageMediaGeo", 0x56e0d474, [F("geo", obj("GeoPoint"))]);
def("MessageMedia", "messageMediaContact", 0x70322949, [F("phone_number", "string"), F("first_name", "string"), F("last_name", "string"), F("vcard", "string"), F("user_id", "long")]);
def("MessageMedia", "messageMediaUnsupported", 0x9f84f49e, []);
def("MessageMedia", "messageMediaDocument", 0x52d8ccd9, [F("flags", "int"), F("document", obj("Document"), 0), F("alt_documents", vec(obj("Document")), 5), F("video_cover", obj("Photo"), 9), F("video_timestamp", "int", 10), F("ttl_seconds", "int", 2)]);
def("MessageMedia", "messageMediaVenue", 0x2ec0533f, [F("geo", obj("GeoPoint")), F("title", "string"), F("address", "string"), F("provider", "string"), F("venue_id", "string"), F("venue_type", "string")]);
def("Game", "game", 0xbdf9653b, [F("flags", "int"), F("id", "long"), F("access_hash", "long"), F("short_name", "string"), F("title", "string"), F("description", "string"), F("photo", obj("Photo")), F("document", obj("Document"), 0)]);
def("MessageMedia", "messageMediaGame", 0xfdb19008, [F("game", obj("Game"))]);
def("MessageMedia", "messageMediaGeoLive", 0xb940c666, [F("flags", "int"), F("geo", obj("GeoPoint")), F("heading", "int", 0), F("period", "int"), F("proximity_notification_radius", "int", 1)]);
def("Poll", "poll", 0x966e2dbf, [F("id", "long"), F("flags", "int"), F("question", obj("TextWithEntities")), F("answers", vec(obj("PollAnswer"))), F("close_period", "int", 4), F("close_date", "int", 5), F("countries_iso2", vec("string"), 12), F("hash", "long")]);
def("PollAnswer", "pollAnswer", 0x4b7d786a, [F("flags", "int"), F("text", obj("TextWithEntities")), F("option", "bytes"), F("media", obj("MessageMedia"), 0)]);
def("PollResults", "pollResults", 0xba7bb15e, [F("flags", "int"), F("results", vec(obj("PollAnswerVoters")), 1), F("total_voters", "int", 2), F("recent_voters", vec(obj("Peer")), 3), F("solution", "string", 4), F("solution_entities", vec(obj("MessageEntity")), 4), F("solution_media", obj("MessageMedia"), 5)]);
def("PollAnswerVoters", "pollAnswerVoters", 0x3645230a, [F("flags", "int"), F("option", "bytes"), F("voters", "int", 2), F("recent_voters", vec(obj("Peer")), 2)]);
def("MessageMedia", "messageMediaPoll", 0x773f4e66, [F("flags", "int"), F("poll", obj("Poll")), F("results", obj("PollResults")), F("attached_media", obj("MessageMedia"), 0)]);
def("MessageMedia", "messageMediaDice", 0x8cbec07, [F("flags", "int"), F("value", "int"), F("emoticon", "string")]);
def("MessageMedia", "messageMediaGiveaway", 0xaa073beb, [F("flags", "int"), F("channels", vec("long")), F("countries_iso2", vec("string"), 1), F("prize_description", "string", 3), F("quantity", "int"), F("months", "int", 4), F("stars", "long", 5), F("until_date", "int")]);
def("MessageMedia", "messageMediaGiveawayResults", 0xceaa3ea1, [F("flags", "int"), F("channel_id", "long"), F("additional_peers_count", "int", 3), F("launch_msg_id", "int"), F("winners_count", "int"), F("unclaimed_count", "int"), F("winners", vec("long")), F("months", "int", 4), F("stars", "long", 5), F("prize_description", "string", 1), F("until_date", "int")]);
def("MessageExtendedMedia", "messageExtendedMediaPreview", 0xad628cc8, [F("flags", "int"), F("w", "int", 0), F("h", "int", 0), F("thumb", obj("PhotoSize"), 1), F("video_duration", "int", 2)]);
def("MessageExtendedMedia", "messageExtendedMedia", 0xee479c64, [F("media", obj("MessageMedia"))]);
def("MessageMedia", "messageMediaPaidMedia", 0xa8852491, [F("stars_amount", "long"), F("extended_media", vec(obj("MessageExtendedMedia")))]);
def("Message", "message", 0x95ef6f2b, [
  F("flags", "int"),
  F("flags2", "int"),
  F("id", "int"),
  F("from_id", obj("Peer"), 8),
  F("from_rank", "string", 12, true),
  F("peer_id", obj("Peer")),
  F("saved_peer_id", obj("Peer"), 28),
  F("fwd_from", obj("MessageFwdHeader"), 2),
  F("via_bot_id", "long", 11),
  F("via_business_bot_id", "long", 0, true),
  F("reply_to", obj("MessageReplyHeader"), 3),
  F("date", "int"),
  F("message", "string"),
  F("media", obj("MessageMedia"), 9),
  F("entities", vec(obj("MessageEntity")), 7),
  F("views", "int", 10),
  F("forwards", "int", 10),
  F("replies", obj("MessageReplies"), 23),
  F("edit_date", "int", 15),
  F("post_author", "string", 16),
  F("grouped_id", "long", 17),
  F("reactions", obj("MessageReactions"), 20),
  F("restriction_reason", vec(obj("RestrictionReason")), 22),
  F("ttl_period", "int", 25),
  F("effect", "long", 2, true),
  F("factcheck", obj("FactCheck"), 3, true),
  F("paid_message_stars", "long", 6, true),
  F("suggested_post", obj("SuggestedPost"), 7, true),
  F("schedule_repeat_period", "int", 10, true),
  F("summary_from_language", "string", 11, true),
]);
def("Messages", "messages.messages", 0x1d73e7ea, [F("messages", vec(obj("Message")))]);
def("Messages", "messages.messagesSlice", 0x5f206716, [F("flags", "int"), F("count", "int"), F("next_rate", "int", 0), F("offset_id_offset", "int", 2), F("messages", vec(obj("Message")))]);
def("Messages", "messages.channelMessages", 0xc776ba4e, [F("flags", "int"), F("pts", "int"), F("count", "int"), F("offset_id_offset", "int", 2), F("messages", vec(obj("Message")))]);
def("Messages", "messages.messagesNotModified", 0x74535f21, [F("count", "int")]);

// ---------- updates results ----------
def("Update", "updateNewMessage", 0x1f2b0afd, [F("message", obj("Message")), F("pts", "int"), F("pts_count", "int")]);
def("Update", "updateNewChannelMessage", 0x62ba04d9, [F("message", obj("Message")), F("pts", "int"), F("pts_count", "int")]);
def("Update", "updateMessageID", 0x4e90bfd6, [F("id", "int"), F("random_id", "long")]);
def("Updates", "updates", 0x74ae4240, [F("updates", vec(obj("Update"))), F("users", vec(obj("User"))), F("chats", vec(obj("Chat"))), F("date", "int"), F("seq", "int")]);
def("Updates", "updatesCombined", 0x725b04c3, [F("updates", vec(obj("Update"))), F("users", vec(obj("User"))), F("chats", vec(obj("Chat"))), F("date", "int"), F("seq_start", "int"), F("seq", "int")]);
def("Updates", "updatesTooLong", 0xe317af7e, []);
def("Updates", "updateShortSentMessage", 0x9015e101, [F("flags", "int"), F("id", "int"), F("pts", "int"), F("pts_count", "int"), F("date", "int"), F("media", obj("MessageMedia"), 9), F("entities", vec(obj("MessageEntity")), 7)]);
def("UpdatesState", "updates.state", 0xa56c2a3e, [F("pts", "int"), F("qts", "int"), F("date", "int"), F("seq", "int"), F("unread_count", "int")]);

// ---------- upload / files ----------
def("StorageFileType", "storage.fileUnknown", 0xaa963b05, []);
def("StorageFileType", "storage.filePartial", 0x40bc6f52, []);
def("StorageFileType", "storage.fileJpeg", 0x7efe0e, []);
def("StorageFileType", "storage.fileGif", 0xcae1aadf, []);
def("StorageFileType", "storage.filePng", 0xa4f63c0, []);
def("StorageFileType", "storage.filePdf", 0xae1e508d, []);
def("StorageFileType", "storage.fileMp3", 0x528a0677, []);
def("StorageFileType", "storage.fileMov", 0x4b09ebbc, []);
def("StorageFileType", "storage.fileMp4", 0xb3cea0e4, []);
def("StorageFileType", "storage.fileWebp", 0x1081464c, []);
def("UploadFile", "upload.file", 0x96a18d5, [F("type", obj("StorageFileType")), F("mtime", "int"), F("bytes", "bytes")]);
def("InputFileLocation", "inputDocumentFileLocation", 0xbad07584, [F("id", "long"), F("access_hash", "long"), F("file_reference", "bytes"), F("thumb_size", "string")]);
def("InputFileLocation", "inputPhotoFileLocation", 0x40181ffe, [F("id", "long"), F("access_hash", "long"), F("file_reference", "bytes"), F("thumb_size", "string")]);
def("InputFile", "inputFile", 0xf52ff27f, [F("id", "long"), F("parts", "int"), F("name", "string"), F("md5_checksum", "string")]);
def("InputFile", "inputFileBig", 0xfa4f0bb5, [F("id", "long"), F("parts", "int"), F("name", "string")]);
def("InputDocument", "inputDocument", 0x1abfb575, [F("id", "long"), F("access_hash", "long"), F("file_reference", "bytes")]);
def("InputPhoto", "inputPhoto", 0x3bb3b94a, [F("id", "long"), F("access_hash", "long"), F("file_reference", "bytes")]);
def("InputMedia", "inputMediaEmpty", 0x9664f57f, []);
def("InputMedia", "inputMediaDocument", 0xa8763ab5, [F("flags", "int"), F("id", obj("InputDocument")), F("video_cover", obj("InputPhoto"), 3), F("video_timestamp", "int", 4), F("ttl_seconds", "int", 0)]);
def("InputMedia", "inputMediaUploadedDocument", 0x37c9330, [F("flags", "int"), F("file", obj("InputFile")), F("thumb", obj("InputFile"), 2), F("mime_type", "string"), F("attributes", vec(obj("DocumentAttribute"))), F("stickers", vec(obj("InputDocument")), 0), F("video_cover", obj("InputPhoto"), 6), F("video_timestamp", "int", 7), F("ttl_seconds", "int", 1)]);
def("InputMedia", "inputMediaUploadedPhoto", 0x7d8375da, [F("flags", "int"), F("file", obj("InputFile")), F("stickers", vec(obj("InputDocument")), 0), F("ttl_seconds", "int", 1), F("video", obj("InputDocument"), 3)]);
def("InputMedia", "inputMediaPhoto", 0xe3af4434, [F("flags", "int"), F("id", obj("InputPhoto")), F("ttl_seconds", "int", 0), F("video", obj("InputDocument"), 2)]);

// ---------- API methods ----------
def("Method", "contacts.resolveUsername", 0x725afbbc, [F("flags", "int"), F("username", "string")]);
def("Method", "users.getFullUser", 0xb60f5918, [F("id", obj("InputUser"))]);
def("Method", "channels.getChannels", 0xa7f6bbb, [F("id", vec(obj("InputChannel")))]);
def("Method", "messages.getChats", 0x49e9528f, [F("id", vec("long"))]);
def("Method", "channels.getParticipants", 0x77ced9d0, [F("channel", obj("InputChannel")), F("filter", obj("ChannelParticipantsFilter")), F("offset", "int"), F("limit", "int"), F("hash", "long")]);
def("Method", "messages.getHistory", 0x4423e6c5, [F("peer", obj("InputPeer")), F("offset_id", "int"), F("offset_date", "int"), F("add_offset", "int"), F("limit", "int"), F("max_id", "int"), F("min_id", "int"), F("hash", "long")]);
def("Method", "messages.getMessages", 0x63c66506, [F("id", vec(obj("InputMessage")))]);
def("Method", "messages.forwardMessages", 0x13704a7c, [F("flags", "int"), F("silent", "true", 5), F("drop_author", "true", 11), F("from_peer", obj("InputPeer")), F("id", vec("int")), F("random_id", vec("long")), F("to_peer", obj("InputPeer"))]);
def("Method", "messages.sendMessage", 0x545cd15a, [F("flags", "int"), F("no_webpage", "true", 1), F("silent", "true", 5), F("peer", obj("InputPeer")), F("message", "string"), F("random_id", "long"), F("entities", vec(obj("MessageEntity")), 3)]);
def("Method", "messages.sendMedia", 0x330e77f, [F("flags", "int"), F("silent", "true", 5), F("peer", obj("InputPeer")), F("media", obj("InputMedia")), F("message", "string"), F("random_id", "long")]);
def("Method", "upload.getFile", 0xbe5335be, [F("flags", "int"), F("location", obj("InputFileLocation")), F("offset", "long"), F("limit", "int")]);
def("Method", "upload.saveFilePart", 0xb304a621, [F("file_id", "long"), F("file_part", "int"), F("bytes", "bytes")]);
def("Method", "upload.saveBigFilePart", 0xde7b673d, [F("file_id", "long"), F("file_part", "int"), F("file_total_parts", "int"), F("bytes", "bytes")]);
def("Method", "channels.editBanned", 0x96e6cd81, [F("channel", obj("InputChannel")), F("participant", obj("InputPeer")), F("banned_rights", obj("ChatBannedRights"))]);
def("Method", "channels.editAdmin", 0x9a98ad68, [F("flags", "int"), F("channel", obj("InputChannel")), F("user_id", obj("InputUser")), F("admin_rights", obj("ChatAdminRights")), F("rank", "string", 0)]);
def("Method", "messages.deleteMessages", 0xe58e95d2, [F("flags", "int"), F("revoke", "true", 0), F("id", vec("int"))]);
def("Type", "messages.affectedMessages", 0x84d19185, [F("pts", "int"), F("pts_count", "int")]);
def("Method", "updates.getState", 0xedd4882a, []);

buildAny();
