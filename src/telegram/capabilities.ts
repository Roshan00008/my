import type { TelegramChatMember } from "./types";
import type { CapabilityEntry } from "../shared/rpcTypes";

export function deriveCapabilities(botMember: TelegramChatMember, chatType: string, accountType: "bot" | "user" = "bot"): CapabilityEntry[] {
  const isCreator = botMember.status === "creator";
  const isAdmin = botMember.status === "administrator" || isCreator;
  const has = (right: keyof TelegramChatMember) => isCreator || (isAdmin && Boolean(botMember[right]));

  const canSend =
    (botMember.status === "member" || isAdmin) &&
    (chatType !== "channel" || has("can_post_messages"));

  // User accounts copy via forwardMessages, not Bot API copyMessage: protected
  // content is handled by download+re-upload instead, and invite-link
  // creation isn't exposed by the minimal MTProto client.
  const canInvite = accountType === "user" ? false : has("can_invite_users");
  const canDelete = accountType === "user" ? true : has("can_delete_messages");

  return [
    {
      key: "invite_link",
      label: "Generate invite link",
      available: canInvite,
      reason: canInvite
        ? undefined
        : accountType === "user"
          ? "not supported for user accounts in this build"
          : "bot lacks the 'Add Users' admin right in this chat",
    },
    {
      key: "ban",
      label: "Ban / unban user",
      available: has("can_restrict_members"),
      reason: has("can_restrict_members") ? undefined : "bot lacks the 'Restrict Members' admin right in this chat",
    },
    {
      key: "promote",
      label: "Promote member",
      available: has("can_promote_members"),
      reason: has("can_promote_members") ? undefined : "bot lacks the 'Add New Admins' admin right in this chat",
    },
    {
      key: "send_message",
      label: "Send message",
      available: canSend,
      reason: canSend ? undefined : "bot cannot post in this chat (not a member with send rights)",
    },
    {
      key: "delete_message",
      label: "Delete message (used by the 'last N' probe)",
      available: canDelete,
      reason: canDelete
        ? accountType === "user"
          ? "user accounts resolve ranges via getHistory — no probe post needed"
          : undefined
        : "bot lacks the 'Delete Messages' admin right in this chat",
    },
  ];
}
