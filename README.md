# pajeon
A read-only irc gateway to public youtube live chat. It includes support for emoji
over a protocol similar to the `twitch.tv` irc server's message tag implementation.

It also supports relaying superchats, memberships, membership gifts, and mod/verified
status.

## How to use
Right now nothing is configurable, if you want to run this yourself:
1. Generate a TLS certificate by running `make_cert.sh` from the repository root.
1. Run the server with `go run`.
1. Connect on TLS at `127.0.0.2:6697` or unencrypted on `127.0.0.2:6667`.

## Custom message tags
Clients that want to recieve custom message tags for displaying superchat/emoji should
report `message-tags` and `youtube.com/tags` caps to recieve the extra metadata.

### Emoji support tags
If support for custom tags is advertised then two additional message tags will be added to every message for emoji metadata.

`emotes`: This tag exactly the `twitch.tv` emotes tag described in https://dev.twitch.tv/docs/irc/tags#privmsg-tags

`emotes-url`: This tag is a map of emote ids used in `emotes` to the url for the emote image. Youtube emotes
are not unique on the platform so this url cannot be derived by the client and is sent instead.

An example implementation of rendering these tags on the client can be found in this [fork of gamja](https://github.com/kkartaltepe/gamja/)

### Superchat support tags
If a message is a superchat it will contain an `amount` tag with the superchat amount and currency. Youtube typically
sends the superchat color directly but we do not pass this metadata along.

### Membership messages
Memberships will be reported by the `service` user as a `NOTICE` and do not contain any extra tags.
