package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// "golang.org/x/time/rate"
	jq "github.com/itchyny/gojq"
	"gopkg.in/irc.v3"
)

const ChatPollDuration = 2 * time.Second
const ircTimeLayout = "2006-01-02T15:04:05.000Z"

func coalesce(ss ...[]ytMessagePart) []ytMessagePart {
    for _, s := range ss {
        if len(s) > 0 {
            return s
        }
    }
    return nil
}

func formatTimeUsec(t string) string {
	intVal, err := strconv.ParseInt(t, 0, 64)
	if err != nil {
		return time.Now().UTC().Format(ircTimeLayout)
	}
	return time.UnixMicro(intVal).Format(ircTimeLayout)
}

func unformatTimeUsc(t string) time.Time {
    if t, e := time.Parse(ircTimeLayout, t); e == nil {
        return t
    }
    return time.Now().UTC()
}

func jqMustCompile(s string) *jq.Code {
	q, err := jq.Parse(s)
	if err != nil {
		panic(err)
	}

	c, err := jq.Compile(q)
	if err != nil {
		panic(err)
	}

	return c
}

type capabilities map[string]bool

func (c capabilities) IsEnabled(cap string) bool {
	// log.Printf("Checking cap %s in %+v", cap, c)
	if b, ok := c[cap]; ok {
		return b
	}
	return false
}

var serverCaps = capabilities{
	"cap-notify":       true,
	"server-time":      true,
	"message-tags":     true,
	"youtube.com/tags": true, // lets follow along with twitch.tv/tags for extended message tags.
}

func getISupport() []string {
	// https://modern.ircdocs.horse/#rplisupport-parameters
	params := map[string]string{
		"AWAYLEN":     "256",
		"CASEMAPPING": "ascii",
		"CHANTYPES":   "#",
		"CHANLIMIT":   "#:",
		"CHANNELLEN":  "256",
		"ELIST":       "", // can this be omited if we dont support any extensions?
		"HOSTLEN":     "64",
		"KICKLEN":     "256",
		"MAXLIST":     "beI:25", // I know nothing of channel modes.
		"NICKLEN":     "8",      // not that you can actually set a nick.
		"PREFIX":      "(qaohv)~&@%+",
		"STATUSMSG":   "~&@%+",
		"TOPICLEN":    "256",
		"USERLEN":     "8",
	}

	ret := []string{}
	for k, v := range params {
		ret = append(ret, fmt.Sprintf("%s=%s", k, v))
	}
	return ret
}

type Client struct {
	*irc.Conn
	id         string
	srv        *Server
	caps       capabilities
	nick       string
	user       string
	registered bool
	capsReg    bool // are we in cap registration? used to wait for CAP END.
	nickReg    string
	userReg    string
	closer     func() error
	msgs       chan *irc.Message
}

func newClient(c net.Conn, s *Server) *Client {
	return &Client{
		Conn: irc.NewConn(c),
		id:   c.RemoteAddr().String(),
		srv:  s,
		caps: capabilities{},
		nick: "anonymous",
		user: "anonymous",
		msgs: make(chan *irc.Message),
		// handle registration phase data.
		registered: false,
		capsReg:    false,
		nickReg:    "",
		userReg:    "",
		closer:     c.Close,
	}
}

func (c *Client) prefix() *irc.Prefix {
	return &irc.Prefix{Name: c.nick, User: c.user, Host: c.id}
}

func (c *Client) Close() error {
	close(c.msgs)
	return c.closer()
}

func (c *Client) SendMessage(msg *irc.Message) {
	if !c.caps.IsEnabled("message-tags") {
		msg = msg.Copy()
		msg.Tags = irc.Tags{}
	}
	if !c.caps.IsEnabled("server-time") {
		delete(msg.Tags, "time")
	}
	if !c.caps.IsEnabled("youtube.com/tags") {
		delete(msg.Tags, "emotes")
		delete(msg.Tags, "emotes-url")
	}
	if msg.Prefix != nil && msg.Prefix.Name == "*" {
		// Set prefix to nil?
	}
	if err := c.WriteMessage(msg); err != nil {
		log.Printf("Failed to send message: %v", err)
	}
}

func (c *Client) handleMessageUnregistered(msg *irc.Message) error {
	// https://modern.ircdocs.horse/#connection-registration
	// Handle initial connection setup and negotiation
	switch msg.Command {
	case "CAP":
		sub := msg.Params[0]
		switch sub {
		case "LS":
			caps := []string{}
			for k, _ := range serverCaps {
				caps = append(caps, k)
			}
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, "LS", strings.Join(caps, " ")},
			}
			c.capsReg = true
		case "REQ":
			capsNames := strings.Fields(msg.Params[1])
			caps := capabilities{}
			ack := true
			for _, cap := range capsNames {
				cap = strings.ToLower(cap)
				enable := !strings.HasPrefix(cap, "-")
				if !enable {
					cap = strings.TrimPrefix(cap, "-")
				}

				if !serverCaps.IsEnabled(cap) {
					ack = false
					break
				}
				caps[cap] = enable
			}

			if ack {
				for cap, enable := range caps {
					c.caps[cap] = enable
				}
			}

			rep := "ACK"
			if !ack {
				rep = "NACK"
			}
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, rep, msg.Params[1]},
			}
		case "END":
			c.capsReg = false
		default:
			return fmt.Errorf("Unknown CAP subcommand: %s", sub)
		}
	case "PASS":
	case "NICK":
		oldPrefix := c.prefix()
		c.nickReg = msg.Params[0]
		c.msgs <- &irc.Message{
			Prefix:  oldPrefix,
			Command: "NICK",
			Params:  []string{c.nick},
		}
	case "USER":
		c.userReg = msg.Params[0]

	case "PONG":
	default:
		return fmt.Errorf("Unknown command during registration: %s", msg.Command)
	}

	if len(c.nickReg) > 0 && len(c.userReg) > 0 && !c.capsReg {
		c.registered = true
		c.nick = c.nickReg
		c.user = c.userReg
	}

	return nil
}

func (c *Client) handleMessageRegistered(msg *irc.Message) error {
	switch msg.Command {
	case "CAP":
		sub := msg.Params[0]
		switch sub {
		case "LS":
			caps := []string{}
			for k, _ := range serverCaps {
				caps = append(caps, k)
			}
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, "LS", strings.Join(caps, " ")},
			}
		case "REQ":
			// We are dumb, you should have requested during registration.
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, "NACK", msg.Params[1]},
			}
		case "END":
		case "LIST":
			caps := []string{}
			for k, _ := range c.caps {
				caps = append(caps, k)
			}
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, "LIST", strings.Join(caps, " ")},
			}
		default:
			return fmt.Errorf("Unknown CAP subcommand: %s", sub)
		}
	case "NICK", "USER":
	case "WHO", "WHOIS", "WHOWAS", "MODE", "AWAY":

	// Channel stuff.
	case "JOIN":
		chans := strings.Split(msg.Params[0], ",")
		for _, id := range chans {
			if err := c.srv.Join(id, c); err != nil {
				log.Printf("Failed to join: %s %v", id, err)
				c.msgs <- &irc.Message{
					Prefix:  c.srv.prefix(),
					Command: irc.ERR_NOSUCHCHANNEL,
					Params:  []string{c.nick, id, fmt.Sprintf("No such channel (%v)", err)},
				}
				c.msgs <- &irc.Message{
					Prefix:  c.prefix(),
					Command: "PART",
					Params:  []string{id},
				}
				continue
			}
			c.msgs <- &irc.Message{
				Prefix:  c.prefix(),
				Command: "JOIN",
				Params:  []string{id},
			}
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_TOPIC,
				Params:  []string{c.nick, id, fmt.Sprintf("https://www.youtube.com/watch?v=%s", strings.TrimPrefix(id, "#"))},
			}
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_NAMREPLY,
				Params:  []string{c.nick, "=", id, c.nick},
			}
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_ENDOFNAMES,
				Params:  []string{c.nick, id, "End of /NAMES list"},
			}
			log.Printf("JOIN success: %s %s", c.nick, id)
		}
	case "PART":
		chans := strings.Split(msg.Params[0], ",")
		for _, id := range chans {
			c.srv.commands <- &Cmd{kind: "INTERNAL_PART", params: []string{c.id, id}}
			// TODO: let this buffer longer but gamja cant handle us buffering parts right now.
			c.srv.hasWork.Store(true)
			c.srv.hasWorkCond.Signal()
		}
	case "NAMES":
		chans := strings.Split(msg.Params[0], ",")
		for _, ch := range chans {
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_NAMREPLY,
				Params:  []string{c.nick, "=", ch, c.nick},
			}
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_ENDOFNAMES,
				Params:  []string{c.nick, ch, "End of /NAMES list"},
			}
		}
	case "LIST":
		// Maybe do this.

	// Message stuff. But we are read only.
	case "PRIVMSG", "NOTICE", "TAGMSG", "TOPIC":

	// Server stuff.
	case "VERSION":
		c.msgs <- &irc.Message{
			Prefix:  c.srv.prefix(),
			Command: irc.RPL_VERSION,
			Params:  []string{c.nick, "42", c.srv.host},
		}
		for _, param := range getISupport() {
			// coalesce into bundles of 13 if we care.
			c.msgs <- &irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_ISUPPORT,
				Params:  []string{c.nick, param, "are supported by this server"},
			}
		}
	case "MOTD", "TIME", "INVITE", "STATS", "HELP", "INFO":

	case "PONG":
	case "PING":
		c.msgs <- &irc.Message{
			Prefix:  c.srv.prefix(),
			Command: "PONG",
			Params:  []string{msg.Params[0]},
		}

	case "QUIT":
		return fmt.Errorf("Connection closing due to QUIT: nick=%s", c.nick)
	default:
		return fmt.Errorf("Unknown command: %s", msg.Command)
	}

	return nil
}

func (c *Client) Serve() error {
	for !c.registered {
		msg, err := c.ReadMessage()
		if err != nil {
			return fmt.Errorf("Error reading message during registration: %v", err)
		}
		log.Printf("Pre-Reg message: %+v", msg)
		if err := c.handleMessageUnregistered(msg); err != nil {
			return fmt.Errorf("Error during registration: %v", err)
		}
	}

	c.msgs <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.RPL_WELCOME,
		Params:  []string{c.nick, "You enter a maze of twisty little passages, all alike."},
	}
	c.msgs <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.RPL_YOURHOST,
		Params:  []string{c.nick, "Your guide is " + c.srv.host},
	}
	c.msgs <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.RPL_MYINFO,
		Params:  []string{c.nick, c.srv.host, "irc", "aiwro0", "OovaimnqpsrtklbeI"}, // I know nothing of modes, but soju does this.
	}
	for _, param := range getISupport() {
		// coalesce into bundles of 13 if we care.
		c.msgs <- &irc.Message{
			Prefix:  c.srv.prefix(),
			Command: irc.RPL_ISUPPORT,
			Params:  []string{c.nick, param, "are supported by this server"},
		}
	}
	c.msgs <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.RPL_UMODEIS,
		Params:  []string{c.nick, "+i"},
	}
	c.msgs <- &irc.Message{
		Prefix:  c.srv.prefix(),
		Command: irc.ERR_NOMOTD,
		Params:  []string{c.nick, "No MOTD"},
	}

	for {
		msg, err := c.ReadMessage()
		log.Printf("Post-Reg message: %+v", msg)
		if err != nil {
			return fmt.Errorf("Error reading message: %v", err)
		}
		if err := c.handleMessageRegistered(msg); err != nil {
			return fmt.Errorf("Error handling message: %v", err)
		}
	}

	return nil
}

func (c *Client) ServeOutgoing() {
	for m := range c.msgs {
		c.SendMessage(m)
	}
}

type ytEmoteInfo struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type ytMessagePart struct {
	Text  string      `json:"text"`
	Emote ytEmoteInfo `json:"emoji"`
}

type ytMessage struct {
	Author        string          `json:"author"`
	Id            string          `json:"id"`
	Type          string          `json:"type"`
	Amount        string          `json:"amount"`
	Badges        []string        `json:"badges"`
	TimestampUsec string          `json:"timestampUsec"`
	Messages      []ytMessagePart `json:"message"`
	SubHeader     []ytMessagePart `json:"headerSubtext"` // make a better name
	PrimaryText   []ytMessagePart `json:"primaryText"`   // make a better name
}

func (m *ytMessage) Process() {
	for i, b := range m.Badges {
		m.Badges[i] = strings.ToLower(strings.Split(b, " ")[0])
	}
	m.Messages = runProcess(m.Messages)
	m.SubHeader = runProcess(m.SubHeader)
	m.PrimaryText = runProcess(m.PrimaryText)
}

func runProcess(r []ytMessagePart) []ytMessagePart {
	// drop empty messages and reduce size of the array.
	drop := 0
	for i, msg := range r {
		if len(msg.Text) > 0 {
			continue
		}
		if len(msg.Emote.Id) == 0 {
		    drop += 1
		    continue
		}

		// Emoji's are their own id and name so we can pick them out fairly
		// easily. We want to pass them along as text and not encode them in
		// the `emotes` and `emotes-url` tags.
		if msg.Emote.Id == msg.Emote.Name {
			r[i].Text = msg.Emote.Name
			r[i].Emote = ytEmoteInfo{}
		}

        if drop > 0 {
            r[i-drop] = r[i]
        }
	}
	return r[0:len(r)-drop]
}

func runToString(r []ytMessagePart) string {
	ret := ""
	for _, msg := range r {
		if len(msg.Text) > 0 {
			ret += msg.Text
		} else if len(msg.Emote.Name) > 0 {
			ret += msg.Emote.Name + " "
		}
	}
	return ret
}

func utf16Len(s string) int {
	l := 0
	for _, r := range s {
		if r <= 0xFFFF {
			l += 1
		} else {
			l += 2
		}
	}
	return l
}

// Emote lengths are in utf16 encoding because the web is fucking terrible, and we want to match twitch.tv/tags for now.
func EmotesTag(msgs []ytMessagePart) string {
	pos := 0
	emoPos := map[string][][]int32{}
	for _, msg := range msgs {
		if len(msg.Text) > 0 {
			pos += utf16Len(msg.Text)
		} else if msg.Emote.Id != "" { // TODO: Why are there empty messages when no message field is in the json
			s := pos
			e := pos + utf16Len(msg.Emote.Name) - 1 // Lets match twitch which uses inclusive end unfortunately.
			pos = e + 1 + 1                         // Because we add a space to String()
			emoPos[msg.Emote.Name] = append(emoPos[msg.Emote.Name], []int32{int32(s), int32(e)})
		}
	}

	isFirstEmote := true
	tag := ""
	for k, v := range emoPos {
		isFirstRange := true
		if isFirstEmote {
			tag += k + ":"
			isFirstEmote = false
		} else {
			tag += "/" + k + ":"
		}
		for _, r := range v {
			if isFirstRange {
				tag += fmt.Sprintf("%d-%d", r[0], r[1])
				isFirstRange = false
			} else {
				tag += fmt.Sprintf(",%d-%d", r[0], r[1])
			}
		}
	}
	return tag
}

func EmotesURLTag(msgs []ytMessagePart) string {
	urls := map[string]string{}
	for _, msg := range msgs {
		if len(msg.Emote.Name) > 0 {
			urls[msg.Emote.Name] = msg.Emote.URL
		}
	}

	// Reuse same separators as `emote`
	// k:v [/k:v ...]
	isFirst := true
	tag := ""
	for k, v := range urls {
		v = base64.StdEncoding.EncodeToString([]byte(v))
		v = strings.ReplaceAll(v, "=", "_")
		if isFirst {
			isFirst = false
			tag += fmt.Sprintf("%s:%s", k, v)
		} else {
			tag += fmt.Sprintf("/%s:%s", k, v)
		}
	}
	return tag
}

// Chat instance mapped to an irc channel.
type chat struct {
	id           string // Live id used to retrieve chat.
	version      string // Junk, but lets pretend we are up to date javascript.
	continuation string // Cursor to server representing what messages have been read so far.
	apiKey       string
	client       *http.Client
	done         chan struct{}
	msgs         chan *irc.Message
	lock         *sync.Mutex
	s            *Server
}

var (
	findInnerAPI     = regexp.MustCompile("\"INNERTUBE_API_KEY\":\"([^\"]*)\"")
	findContinuation = regexp.MustCompile("\"continuation\":\"([^\"]*)\"")
	findVersion      = regexp.MustCompile("\"clientVersion\":\"([^\"]*)\"")
	findFirstContext = regexp.MustCompile("{\"responseContext\"")
	// Bless, and curse jq
	jsonFilter = jqMustCompile(`
    def parse_text: [
        (if (.runs | length > 0) then .runs[]  else {text: .simpleText} end) | {
	        emoji: {id: .emoji.emojiId, name: .emoji.image.accessibility.accessibilityData.label, url: .emoji.image.thumbnails[0].url},
	        text: .text,
	    }
    ];
	.. | select(type == "object") |
	if has("liveChatPaidMessageRenderer") then .liveChatPaidMessageRenderer + {type: "super"}
	elif has("liveChatTextMessageRenderer") then .liveChatTextMessageRenderer + {type: "chat"}
	elif has("liveChatMembershipItemRenderer") then .liveChatMembershipItemRenderer + {type: "member"}
	elif has("liveChatSponsorshipsGiftPurchaseAnnouncementRenderer") then .liveChatSponsorshipsGiftPurchaseAnnouncementRenderer.header.liveChatSponsorshipsHeaderRenderer + {type: "member_gifter"}
	elif has("liveChatSponsorshipsGiftRedemptionAnnouncementRenderer") then .liveChatSponsorshipsGiftRedemptionAnnouncementRenderer + {type: "member_giftee"}
	else null end
	| select ( . != null) |
	{
	    author: .authorName.simpleText, id, timestampUsec, type,
	    badges:  (if (.authorBadges | length > 0) then [.authorBadges[] | .liveChatAuthorBadgeRenderer.accessibility.accessibilityData.label] else null end),
	    amount: .purchaseAmountText.simpleText,
	    message: .message | parse_text,
	    headerSubtext: .headerSubtext | parse_text,
	    primaryText: .primaryText | parse_text,
	}`)
)

func (c *chat) extractAndSend(data map[string]interface{}, slowSend bool) error {
	toSend := make([]*irc.Message, 0, 64)
	iter := jsonFilter.Run(data)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return fmt.Errorf("Bad YT chat response: %v", err)
		}
		// Do something with iter
		enc, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("Bad YT chat response: %v", err)
		}
		ytMsg := ytMessage{}
		if err := json.Unmarshal(enc, &ytMsg); err != nil {
			return fmt.Errorf("Bad YT chat parse: %v", err)
		}
		ytMsg.Process() // do some filtering: emoji passthrough, badge normalization

		tags := irc.Tags{}
		if len(ytMsg.Amount) > 0 {
			tags["amount"] = irc.TagValue(ytMsg.Amount)
		}
		if len(ytMsg.Badges) > 0 {
			// badge/value,badge/value
			tags["badges"] = irc.TagValue(strings.Join(ytMsg.Badges, ","))
		}

		ircCmd := "PRIVMSG"
		ircAuthor := strings.ReplaceAll(strings.ReplaceAll(ytMsg.Author, " ", "_"), "!", "！")
		ircMsg := ytMsg.Messages // we are going to mutate this, but golang does give a fuck.
		if ytMsg.Type == "member" {
		    prim := ytMsg.PrimaryText
		    sub := ytMsg.SubHeader
            msg := coalesce(ircMsg, prim, sub)

			svcMsg := "New Membership, "
			if len(ircMsg) != 0 {
                svcMsg = "Membership renewed, "
		    }

			ircMsg = append([]ytMessagePart{{Text: svcMsg + ircAuthor + " - "}}, msg...)
			ircAuthor = "services"
			ircCmd = "NOTICE"
		}
		if ytMsg.Type == "member_gifter" {
			ircMsg = append([]ytMessagePart{{Text: ircAuthor + " "}}, ytMsg.PrimaryText...)
			ircAuthor = "services"
			ircCmd = "NOTICE"
		}
		if ytMsg.Type == "member_giftee" {
			ircMsg = append([]ytMessagePart{{Text: ircAuthor + " "}}, ytMsg.Messages...)
			ircAuthor = "services"
			ircCmd = "NOTICE"
		}

		tags["time"] = irc.TagValue(formatTimeUsec(ytMsg.TimestampUsec))
		tags["emotes"] = irc.TagValue(EmotesTag(ircMsg))
		tags["emotes-url"] = irc.TagValue(EmotesURLTag(ircMsg))
		toSend = append(toSend, &irc.Message{
			Prefix:  &irc.Prefix{Name: ircAuthor},
			Command: ircCmd,
			Params:  []string{c.id, runToString(ircMsg)},
			Tags:    tags,
		})
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	select {
	case <-c.done:
		return nil
	default:
	    if len(toSend) < 1 {
	        return nil
	    }
	    if !slowSend {
		    for _, m := range toSend {
			    c.msgs <- m
			}
			c.s.hasWork.Store(true)
			c.s.hasWorkCond.Signal()
			return nil
	    }
	    base := unformatTimeUsc(string(toSend[0].Tags["time"]))
	    baseNow := time.Now()
		for _, m := range toSend {
		    // drip feed at the right rate for the messages recieved
		    delay := time.Until(baseNow.Add(unformatTimeUsc(string(m.Tags["time"])).Sub(base)))
		    if delay > 0 {
		        time.Sleep(delay)
		    }
			c.msgs <- m
			c.s.hasWork.Store(true)
			c.s.hasWorkCond.Signal()
		}
	}
	return nil
}

func (c *chat) readChat(slowSend bool) error {
	getLiveChatBody := fmt.Sprintf(`{"context": {"client":{"hl":"en","gl":"US","clientName":"WEB","clientVersion":"%s","platform":"DESKTOP"}},"continuation": "%s"}`, c.version, c.continuation)
	req, err := http.NewRequest("POST", fmt.Sprintf("https://www.youtube.com/youtubei/v1/live_chat/get_live_chat?key=%s&prettyPrint=false", c.apiKey), strings.NewReader(getLiveChatBody))
	if err != nil {
		return fmt.Errorf("Bad YT chat request: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("Bad YT chat response: %v", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Bad YT chat response: %v", err)
	}

	contMatch := findContinuation.FindAllStringSubmatch(string(body), -1)
	if len(contMatch) < 1 {
		return fmt.Errorf("Couldnt find continuation for chat: %s", c.id)
	}
	c.continuation = contMatch[0][1]

	idata := map[string]interface{}{}
	if err := json.Unmarshal(body, &idata); err != nil {
		return fmt.Errorf("Bad YT chat response: %v", err)
	}

	if err := c.extractAndSend(idata, slowSend); err != nil {
	    log.Printf("Error reading chat: %v", err)
	}
	return nil
}

func (c *chat) Close() {
	c.lock.Lock()
	close(c.done)
	close(c.msgs)
	c.lock.Unlock()
}

func NewChat(id string, s *Server) (*chat, error) {
	id = strings.TrimPrefix(id, "#")
	client := &http.Client{}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.youtube.com/live_chat?is_popout=1&v=%s", id), nil)
	if err != nil {
		return nil, fmt.Errorf("Bad YT request: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Bad YT response: %v", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Bad YT response: %v", err)
	}

	apiMatch := findInnerAPI.FindStringSubmatch(string(body))
	if len(apiMatch) < 2 {
		return nil, fmt.Errorf("Couldnt find inner API key")
	}
	innerAPIKey := strings.ReplaceAll(apiMatch[1], "\n", "")

	contMatch := findContinuation.FindAllStringSubmatch(string(body), -1)
	if len(contMatch) < 3 || len(contMatch[2]) < 2 {
		return nil, fmt.Errorf("Couldnt find chat continuation")
	}
	cont := strings.ReplaceAll(contMatch[2][1], "\n", "")

	versionMatch := findVersion.FindStringSubmatch(string(body))
	if len(versionMatch) < 2 {
		return nil, fmt.Errorf("Couldnt find web client version")
	}
	version := strings.ReplaceAll(versionMatch[1], "\n", "")

	chat := &chat{
		id:           "#" + id,
		version:      version,
		client:       client,
		apiKey:       innerAPIKey,
		continuation: cont,
		done:         make(chan struct{}),
		msgs:         make(chan *irc.Message, 256),
		lock:         &sync.Mutex{},
		s:            s,
	}

	// Read the history and send it down.
	if err := chat.readChat(false); err != nil {
		chat.Close()
		return nil, fmt.Errorf("Chat closed due to an error: %v", err)
	}

	go func() {
		tick := time.NewTicker(ChatPollDuration)
		defer tick.Stop()
		for {
			select {
			case <-chat.done:
				log.Printf("Closing %s reader", chat.id)
				return
			case <-tick.C:
				if err := chat.readChat(true); err != nil {
					s.commands <- &Cmd{kind: "CLOSECHAN", params: []string{chat.id}}
					s.hasWork.Store(true)
					s.hasWorkCond.Signal()
					log.Printf("Chat closed due to error: %v", err)
					return
				}
			}
		}
	}()

	return chat, nil
}

// Simple commands for internal work to be serialized.
type Cmd struct {
	kind   string
	params []string
}

type Server struct {
	host     string
	clients  map[string]*Client
	members  map[string]map[string]*Client
	chats    map[string]*chat
	done     chan struct{}
	commands chan *Cmd

	hasWorkCond *sync.Cond
	hasWork     atomic.Value // bool
}

func (s *Server) ServeClients(l net.Listener) error {
	for {
		conn, err := l.Accept()
		log.Printf("Got connection: %s", conn.RemoteAddr().String())
		if errors.Is(err, net.ErrClosed) {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to accept conn: %v", err)
		}

		go func() {
			c := newClient(conn, s)
			// TODO: Lock
			s.clients[c.id] = c
			defer func() {
				c.Close()
				delete(s.clients, c.id)
			}()
			go c.ServeOutgoing()
			if err := c.Serve(); err != nil {
				log.Printf("Client disconnected: %s", err)
			}
		}()
	}
}

func (s *Server) HandleCommand(cmd *Cmd) {
	switch cmd.kind {
	case "CLOSECHAN":
		id := cmd.params[0]
		s.CloseChannel(id)
	case "INTERNAL_PART":
		c, ok := s.clients[cmd.params[0]]
		if !ok { log.Print("Parting but no such client"); return }
		channel, ok := s.chats[cmd.params[1]]
		if !ok { log.Print("Parting but no such channel"); return }

		if err := s.Part(channel.id, c); err != nil {
			c.msgs <- &irc.Message{
				Prefix:  s.prefix(),
				Command: irc.ERR_NOSUCHCHANNEL,
				Params:  []string{c.nick, channel.id, fmt.Sprintf("No such channel (%v)", err)},
			}
		}

		c.msgs <- &irc.Message{
			Prefix:  c.prefix(),
			Command: "PART",
			Params:  []string{channel.id},
		}
	default:
		log.Printf("Unknown internal cmd: %v", cmd)
	}
}

func (s *Server) ServeMessages() {
	msgs := make([]*irc.Message, 64)
	for {
		s.hasWork.Store(false)

		for _, c := range s.chats {
			msgs = msgs[:0] // clear

		FULL:
			for {
				select {
				case m, ok := <-c.msgs:
					if !ok {
						break FULL
					}
					msgs = append(msgs, m)
				default:
					break FULL
				}
			}

			for _, client := range s.members[c.id] {
				for _, m := range msgs {
					client.msgs <- m
				}
			}
		}

		// Handle internal work.
	DONE:
		for {
			select {
			case m, ok := <-s.commands:
				if !ok {
					break DONE
				}
				s.HandleCommand(m)
			default:
				break DONE
			}
		}

		if s.hasWork.Load().(bool) {
			continue
		}
		s.hasWorkCond.L.Lock()
		s.hasWorkCond.Wait()
		s.hasWorkCond.L.Unlock()
	}
}

func (s *Server) Join(id string, client *Client) error {
	if _, ok := s.chats[id]; ok {
		s.members[id][client.id] = client
		return nil
	}

	// so we can send initial messages in NewChat
	s.members[id] = map[string]*Client{client.id: client}
	c, err := NewChat(id, s)
	if err != nil {
		return err
	}
	s.chats[id] = c
	return nil
}

func (s *Server) Part(id string, client *Client) error {
	if _, ok := s.chats[id]; !ok {
		return errors.New("no such channel")
	}

	delete(s.members[id], client.id)
	if len(s.members[id]) == 0 {
		s.CloseChannel(id)
	}
	return nil
}

func (s *Server) CloseChannel(id string) error {
	if _, ok := s.chats[id]; !ok {
		return errors.New("no such channel")
	}
	s.chats[id].Close()

	for _, c := range s.members[id] {
		c.msgs <- &irc.Message{
			Prefix:  c.prefix(),
			Command: "PART",
			Params:  []string{id},
		}
	}

	delete(s.chats, id)
	delete(s.members, id)

	return nil
}

func (s *Server) prefix() *irc.Prefix {
	return &irc.Prefix{Name: s.host}
}

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("Couldnt load tls cert: %s", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"irc"},
	}

	lc := net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.2:6697")
	if err != nil {
		log.Fatalf("Failed to listen on localhost: %s", err)
	}
	ln := tls.NewListener(l, tlsConfig)

	l2, err := net.Listen("tcp", "127.0.0.2:6667")
	if err != nil {
		log.Fatalf("Failed to listen on non-tls localhost: %s", err)
	}

	srv := &Server{
		host:     "irc.notyoutube.local",
		clients:  map[string]*Client{},
		chats:    map[string]*chat{},
		members:  map[string]map[string]*Client{},
		commands: make(chan *Cmd, 16),

		hasWorkCond: sync.NewCond(&sync.Mutex{}),
		hasWork:     atomic.Value{},
	}
	srv.hasWork.Store(false)

	go srv.ServeMessages()
	go func() {
		if err := srv.ServeClients(l2); err != nil {
			log.Printf("Error serving on %s: %v", l2, err)
		}
	}()

	if err := srv.ServeClients(ln); err != nil {
		log.Printf("Error serving on %s: %v", ln, err)
	}
}
