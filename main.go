package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	// "golang.org/x/time/rate"
	jq "github.com/itchyny/gojq"
	"gopkg.in/irc.v3"
)

const ChatPollDuration = 2 * time.Second
const ircTimeLayout = "2006-01-02T15:04:05.000Z"

func formatTimeUsec(t string) string {
	intVal, err := strconv.ParseInt(t, 0, 64)
	if err != nil {
		return time.Now().UTC().Format(ircTimeLayout)
	}
	return time.UnixMicro(intVal).Format(ircTimeLayout)
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
	srv        *Server
	registered bool
	caps       capabilities
	nick       string
	user       string
	capsReg    bool // are we in cap registration? used to wait for CAP END.
	nickReg    string
	userReg    string
	closer     func() error
}

func newClient(c io.ReadWriteCloser, s *Server) *Client {
	return &Client{
		Conn:       irc.NewConn(c),
		srv:        s,
		registered: false,
		caps:       capabilities{},
		nick:       "*",
		user:       "anonymous",
		// handle registration phase data.
		capsReg: false,
		nickReg: "",
		userReg: "",
		closer:  c.Close,
	}
}

func (c *Client) Close() error {
	return c.closer()
}

func (c *Client) SendMessage(msg *irc.Message) {
	if !c.caps.IsEnabled("message-tag") {
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
		log.Printf("Failed to send message: %v")
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
			c.SendMessage(&irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, "LS", strings.Join(caps, " ")},
			})
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
			c.SendMessage(&irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, rep, msg.Params[1]},
			})
		case "END":
			c.capsReg = false
		default:
			return fmt.Errorf("Unknown CAP subcommand: %s", sub)
		}
	case "PASS":
	case "NICK":
		c.nickReg = msg.Params[0]
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
			c.SendMessage(&irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, "LS", strings.Join(caps, " ")},
			})
		case "REQ":
			// We are dumb, you should have requested during registration.
			c.SendMessage(&irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, "NACK", msg.Params[1]},
			})
		case "END":
		case "LIST":
			caps := []string{}
			for k, _ := range c.caps {
				caps = append(caps, k)
			}
			c.SendMessage(&irc.Message{
				Prefix:  c.srv.prefix(),
				Command: "CAP",
				Params:  []string{c.nick, "LIST", strings.Join(caps, " ")},
			})
		default:
			return fmt.Errorf("Unknown CAP subcommand: %s", sub)
		}
	case "NICK":
		c.nick = msg.Params[0]
	case "USER":
		c.user = msg.Params[0]
	case "WHO", "WHOIS", "WHOWAS", "MODE":

	// Channel stuff.
	case "JOIN":
		chans := strings.Split(msg.Params[0], ",")
		for _, id := range chans {
			id = strings.TrimPrefix(id, "#")
			if err := c.srv.Join(id, c); err != nil {
				log.Printf("Failed to join: %v", err)
				c.SendMessage(&irc.Message{
					Prefix:  c.srv.prefix(),
					Command: irc.ERR_NOSUCHCHANNEL,
					Params:  []string{c.nick, id, fmt.Sprintf("No such channel (%v)", err)},
				})
			} else {
				c.SendMessage(&irc.Message{
					Prefix:  c.srv.prefix(),
					Command: "JOIN",
					Params:  []string{id},
				})
				c.SendMessage(&irc.Message{
					Prefix:  c.srv.prefix(),
					Command: irc.RPL_TOPIC,
					Params:  []string{c.nick, id, fmt.Sprintf("https://www.youtube.com/watch?v=%s", id)},
				})
				c.SendMessage(&irc.Message{
					Prefix:  c.srv.prefix(),
					Command: irc.RPL_NAMREPLY,
					Params:  []string{c.nick, "=", id, c.nick},
				})
				c.SendMessage(&irc.Message{
					Prefix:  c.srv.prefix(),
					Command: irc.RPL_ENDOFNAMES,
					Params:  []string{c.nick, id, "End of /NAMES list"},
				})
			}
		}
	case "PART":
		chans := strings.Split(msg.Params[0], ",")
		for _, id := range chans {
			if err := c.srv.Part(id); err != nil {
				c.SendMessage(&irc.Message{
					Prefix:  c.srv.prefix(),
					Command: irc.ERR_NOSUCHCHANNEL,
					Params:  []string{c.nick, id, fmt.Sprintf("No such channel (%v)", err)},
				})
			} else {
				c.SendMessage(&irc.Message{
					Prefix:  c.srv.prefix(),
					Command: "PART",
					Params:  []string{id},
				})
			}
		}
	case "NAMES":
		chans := strings.Split(msg.Params[0], ",")
		for _, ch := range chans {
			c.SendMessage(&irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_NAMREPLY,
				Params:  []string{c.nick, "=", ch, c.nick},
			})
			c.SendMessage(&irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_ENDOFNAMES,
				Params:  []string{c.nick, ch, "End of /NAMES list"},
			})
		}
	case "LIST":
		// Maybe do this.

	// Message stuff. But we are read only.
	case "PRIVMSG", "NOTICE", "TAGMSG", "TOPIC":

	// Server stuff.
	case "VERSION":
		c.SendMessage(&irc.Message{
			Prefix:  c.srv.prefix(),
			Command: irc.RPL_VERSION,
			Params:  []string{c.nick, "42", c.srv.host},
		})
		for _, param := range getISupport() {
			// coalesce into bundles of 13 if we care.
			c.SendMessage(&irc.Message{
				Prefix:  c.srv.prefix(),
				Command: irc.RPL_ISUPPORT,
				Params:  []string{c.nick, param, "are supported by this server"},
			})
		}
	case "MOTD", "TIME", "INVITE", "STATS", "HELP", "INFO":

	case "PONG":
	case "PING":
		c.SendMessage(&irc.Message{
			Prefix:  c.srv.prefix(),
			Command: "PONG",
			Params:  []string{msg.Params[0]},
		})

	case "QUIT":
		return fmt.Errorf("Connection closing due to QUIT: nick=%s", c.nick)
	default:
		return fmt.Errorf("Unknown command: %s", msg.Command)
	}

	return nil
}

// Chat instance mapped to an irc channel.
type chat struct {
	id           string
	version      string
	continuation string
	apiKey       string
	client       *http.Client
	ircClient    *Client
	done         chan struct{}
}

type ytEmoteInfo struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	Url  string `json:"url"`
}

type ytMessagePart struct {
	Text  string      `json:"text"`
	Emote ytEmoteInfo `json:"emoji"`
}

type ytMessage struct {
	Author        string          `json:"author"`
	Id            string          `json:"id"`
	TimestampUsec string          `json:"timestampUsec"`
	Messages      []ytMessagePart `json:"message"`
}

func (m *ytMessage) String() string {
	ret := ""
	for _, msg := range m.Messages {
		if len(msg.Text) > 0 {
			ret += msg.Text
		} else {
			ret += msg.Emote.Name
		}
	}
	return ret
}

func (m *ytMessage) EmotesTag() string {
	pos := 0
	emoPos := map[string][][]int32{}
	for _, msg := range m.Messages {
		if len(msg.Text) > 0 {
			pos += len(msg.Text)
		} else {
			s := pos
			e := pos + len(msg.Emote.Name)
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

var (
	findInnerAPI     = regexp.MustCompile("\"INNERTUBE_API_KEY\":\"([^\"]*)\"")
	findContinuation = regexp.MustCompile("\"continuation\":\"([^\"]*)\"")
	findVersion      = regexp.MustCompile("\"clientVersion\":\"([^\"]*)\"")
	// Bless jq
	jsonFilter = jqMustCompile(".. | select(.liveChatTextMessageRenderer? != null).liveChatTextMessageRenderer | {author: .authorName.simpleText, id, timestampUsec, message: [.message.runs[] | {emoji: {id: .emoji.emojiId, name: .emoji.image.accessibility.accessibilityData.label, url: .emoji.image.thumbnails[0].url}, text: .text} ]}")
)

func (c *chat) readChat() error {
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

	iter := jsonFilter.Run(idata)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return fmt.Errorf("Bad YT chat response: %v", err)
		}
		log.Printf("raw jq'ed: %+v", v)
		// Do something with iter
		enc, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("Bad YT chat response: %v", err)
		}
		log.Printf("re-encoded: %s", string(enc))
		ytMsg := ytMessage{}
		if err := json.Unmarshal(enc, &ytMsg); err != nil {
			return fmt.Errorf("Bad YT chat response: %v", err)
		}
		log.Printf("Got message: %s (raw: %+v)", ytMsg.String(), ytMsg)
		tags := irc.Tags{}
		tags["time"] = irc.TagValue(formatTimeUsec(ytMsg.TimestampUsec))
		tags["emotes"] = irc.TagValue(ytMsg.EmotesTag())
		c.ircClient.SendMessage(&irc.Message{
			Prefix:  &irc.Prefix{Name: strings.ReplaceAll(ytMsg.Author, " ", "_")},
			Command: "PRIVMSG",
			Params:  []string{"#" + c.id, ytMsg.String()},
			Tags:    tags,
		})
	}

	return nil
}

func (c *chat) Close() {
	// TODO: part all chats so they close properly
	close(c.done)
}

func joinChat(id string, c *Client) (*chat, error) {
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
		log.Printf("body: %s", string(body))
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
		id:           id,
		version:      version,
		ircClient:    c,
		client:       client,
		apiKey:       innerAPIKey,
		continuation: cont,
		done:         make(chan struct{}),
	}

	go func() {
		tick := time.NewTicker(ChatPollDuration)
		defer tick.Stop()
		for {
			select {
			case <-chat.done:
				return
			case <-tick.C:
				if err := chat.readChat(); err != nil {
					chat.Close()
					log.Printf("Chat closed due to error: %v", err)
					return
				}
			}
		}
	}()

	//TODO: Check that chat is still live here to prevent joins.
	return chat, nil
}

type Server struct {
	host  string
	chats map[string]*chat
}

func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to accept conn: %v", err)
		}

		go func() {
			if err := s.handleClient(newClient(conn, s)); err != nil {
				log.Printf("Client disconnected: %s", err)
			}
		}()
	}
}

func (s *Server) Join(id string, client *Client) error {
	if _, ok := s.chats[id]; ok {
		return nil
	}

	c, err := joinChat(id, client)
	if err != nil {
		return err
	}
	s.chats[id] = c
	return nil
}

func (s *Server) Part(id string) error {
	if _, ok := s.chats[id]; !ok {
		return errors.New("no such channel")
	}

	s.chats[id].Close()
	// TODO: Wait on goroutine finishing.
	delete(s.chats, id)
	return nil
}

func (s *Server) prefix() *irc.Prefix {
	return &irc.Prefix{Name: s.host}
}

func (s *Server) handleClient(c *Client) error {
	defer c.Close()
	for !c.registered {
		msg, err := c.ReadMessage()
		if err != nil {
			return fmt.Errorf("Error reading message during registration: %v", err)
		}
		if err := c.handleMessageUnregistered(msg); err != nil {
			return fmt.Errorf("Error during registration: %v", err)
		}
	}
	log.Printf("User registered: %s", c.nick)

	c.SendMessage(&irc.Message{
		Prefix:  s.prefix(),
		Command: irc.RPL_WELCOME,
		Params:  []string{c.nick, "You enter a maze of twisty little passages, all alike."},
	})
	c.SendMessage(&irc.Message{
		Prefix:  s.prefix(),
		Command: irc.RPL_YOURHOST,
		Params:  []string{c.nick, "Your guide is " + s.host},
	})
	c.SendMessage(&irc.Message{
		Prefix:  s.prefix(),
		Command: irc.RPL_MYINFO,
		Params:  []string{c.nick, s.host, "irc", "aiwro0", "OovaimnqpsrtklbeI"}, // I know nothing of modes, but soju does this.
	})
	for _, param := range getISupport() {
		// coalesce into bundles of 13 if we care.
		c.SendMessage(&irc.Message{
			Prefix:  s.prefix(),
			Command: irc.RPL_ISUPPORT,
			Params:  []string{c.nick, param, "are supported by this server"},
		})
	}
	c.SendMessage(&irc.Message{
		Prefix:  s.prefix(),
		Command: irc.RPL_UMODEIS,
		Params:  []string{c.nick, "+i"},
	})
	c.SendMessage(&irc.Message{
		Prefix:  s.prefix(),
		Command: irc.ERR_NOMOTD,
		Params:  []string{c.nick, "No MOTD"},
	})

	for {
		msg, err := c.ReadMessage()
		if err != nil {
			return fmt.Errorf("Error reading message: %v", err)
		}
		if err := c.handleMessageRegistered(msg); err != nil {
			return fmt.Errorf("Error handling message: %v", err)
		}
	}

	return nil
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
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:6697")
	if err != nil {
		log.Fatalf("Failed to listen on localhost: %s", err)
	}
	ln := tls.NewListener(l, tlsConfig)

	srv := &Server{host: "irc.notyoutube.local", chats: map[string]*chat{}}
	if err := srv.Serve(ln); err != nil {
		log.Printf("Error serving on %s: %v", ln, err)
	}
}
