package bot

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"wgvpn/internal/config"
	"wgvpn/internal/wireguard"
)

type Bot struct {
	api     *tgbotapi.BotAPI
	cfg     *config.Config
	wg      *wireguard.WireGuard
	pending map[int64]string // chatID → pending action
}

func New(cfg *config.Config) (*Bot, error) {
	api, err := tgbotapi.NewBotAPI(cfg.TelegramToken)
	if err != nil {
		return nil, fmt.Errorf("telegram init: %w", err)
	}
	wg, err := wireguard.New(cfg)
	if err != nil {
		return nil, err
	}
	log.Printf("bot authorized as @%s", api.Self.UserName)
	return &Bot{api: api, cfg: cfg, wg: wg, pending: make(map[int64]string)}, nil
}

func (b *Bot) Run() {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	for update := range b.api.GetUpdatesChan(u) {
		if update.Message == nil {
			continue
		}
		msg := update.Message
		if !b.isAdmin(msg.From.ID) {
			b.send(msg.Chat.ID, "Access denied.")
			continue
		}
		if msg.IsCommand() {
			b.dispatch(msg)
		} else {
			b.handleText(msg)
		}
	}
}

func (b *Bot) isAdmin(userID int64) bool {
	return slices.Contains(b.cfg.AdminIDs, userID)
}

func (b *Bot) dispatch(msg *tgbotapi.Message) {
	args := strings.Fields(msg.CommandArguments())
	chat := msg.Chat.ID

	// Any command clears a pending state.
	delete(b.pending, chat)

	switch msg.Command() {
	case "start", "help":
		b.send(chat, helpText)

	case "adduser":
		if len(args) == 1 {
			b.cmdAddUser(chat, args[0])
		} else {
			b.pending[chat] = "adduser"
			b.sendPrompt(chat, "Введи логин нового пользователя:")
		}

	case "deluser":
		if len(args) == 1 {
			b.cmdDelUser(chat, args[0])
		} else {
			b.pending[chat] = "deluser"
			b.sendPrompt(chat, "Введи логин пользователя для удаления:")
		}

	case "listusers":
		b.cmdListUsers(chat)

	case "getconfig":
		if len(args) == 1 {
			b.cmdGetConfig(chat, args[0])
		} else {
			b.pending[chat] = "getconfig"
			b.sendPrompt(chat, "Введи логин пользователя:")
		}

	case "cancel":
		b.send(chat, "Отменено.")

	case "wgstate":
		b.cmdWGState(chat)

	case "startwg":
		b.cmdStartWG(chat)

	case "stopwg":
		b.cmdStopWG(chat)

	case "status":
		b.cmdStatus(chat)

	default:
		b.send(chat, "Unknown command. /help for list.")
	}
}

func (b *Bot) handleText(msg *tgbotapi.Message) {
	chat := msg.Chat.ID
	action, ok := b.pending[chat]
	if !ok {
		return
	}
	delete(b.pending, chat)

	arg := strings.TrimSpace(msg.Text)
	switch action {
	case "adduser":
		b.cmdAddUser(chat, arg)
	case "deluser":
		b.cmdDelUser(chat, arg)
	case "getconfig":
		b.cmdGetConfig(chat, arg)
	}
}

func (b *Bot) cmdAddUser(chat int64, login string) {
	if !validLogin(login) {
		b.send(chat, "Invalid login. Use letters, digits, `_` or `-` (max 32 chars).")
		return
	}
	user, err := b.wg.AddUser(login)
	if err != nil {
		b.send(chat, fmt.Sprintf("Error: %v", err))
		return
	}
	b.send(chat, fmt.Sprintf("User *%s* added, IP: `%s`", login, user.AllowedIPs))
	b.sendFile(chat, fmt.Sprintf("wg-%s.conf", login), b.wg.ClientConfig(user), configCaption)
}

func (b *Bot) cmdDelUser(chat int64, login string) {
	if err := b.wg.DelUser(login); err != nil {
		b.send(chat, fmt.Sprintf("Error: %v", err))
		return
	}
	b.send(chat, fmt.Sprintf("User *%s* removed.", login))
}

func (b *Bot) cmdListUsers(chat int64) {
	users := b.wg.ListUsers()
	if len(users) == 0 {
		b.send(chat, "No users configured.")
		return
	}

	stats := b.wg.PeerStatsMap() // nil if interface is down

	var sb strings.Builder
	fmt.Fprintf(&sb, "*Peers (%d):*\n\n", len(users))

	for i, u := range users {
		ip := strings.TrimSuffix(u.AllowedIPs, "/32")
		fmt.Fprintf(&sb, "%d. *%s*\n", i+1, u.Login)
		fmt.Fprintf(&sb, "   IP:  `%s`\n", ip)
		fmt.Fprintf(&sb, "   Key: `%s…`\n", u.PublicKey[:8])

		if stats != nil {
			if s, ok := stats[u.PublicKey]; ok && !s.LastHandshake.IsZero() {
				fmt.Fprintf(&sb, "   Handshake: %s\n", agoString(s.LastHandshake))
				fmt.Fprintf(&sb, "   Traffic:   rx %s / tx %s\n", formatBytes(s.RxBytes), formatBytes(s.TxBytes))
			} else {
				sb.WriteString("   Handshake: never\n")
			}
		}
		sb.WriteString("\n")
	}

	b.send(chat, strings.TrimRight(sb.String(), "\n"))
}

func agoString(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

func formatBytes(n int64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/k/k)
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/k/k/k)
	}
}

func (b *Bot) cmdGetConfig(chat int64, login string) {
	user, ok := b.wg.GetUser(login)
	if !ok {
		b.send(chat, fmt.Sprintf("User %q not found.", login))
		return
	}
	b.sendFile(chat, fmt.Sprintf("wg-%s.conf", login), b.wg.ClientConfig(user), configCaption)
}

func (b *Bot) cmdWGState(chat int64) {
	if b.wg.IsActive() {
		b.send(chat, "WireGuard: *running*")
	} else {
		b.send(chat, "WireGuard: *stopped*")
	}
}

func (b *Bot) cmdStartWG(chat int64) {
	if err := b.wg.StartService(); err != nil {
		b.send(chat, fmt.Sprintf("Error: %v", err))
		return
	}
	b.send(chat, "WireGuard started.")
}

func (b *Bot) cmdStopWG(chat int64) {
	if err := b.wg.StopService(); err != nil {
		b.send(chat, fmt.Sprintf("Error: %v", err))
		return
	}
	b.send(chat, "WireGuard stopped.")
}

func (b *Bot) cmdStatus(chat int64) {
	out, err := b.wg.Status()
	if err != nil {
		b.send(chat, fmt.Sprintf("Error: %v", err))
		return
	}
	if out == "" {
		out = "No active peers."
	}
	b.send(chat, fmt.Sprintf("```\n%s\n```", out))
}

func (b *Bot) send(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeMarkdown
	if _, err := b.api.Send(msg); err != nil {
		log.Printf("send: %v", err)
	}
}

func (b *Bot) sendPrompt(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ReplyMarkup = tgbotapi.ForceReply{ForceReply: true, Selective: true}
	if _, err := b.api.Send(msg); err != nil {
		log.Printf("sendPrompt: %v", err)
	}
}

func (b *Bot) sendFile(chatID int64, name, content, caption string) {
	doc := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{
		Name:  name,
		Bytes: []byte(content),
	})
	if caption != "" {
		doc.Caption = caption
		doc.ParseMode = tgbotapi.ModeMarkdown
	}
	if _, err := b.api.Send(doc); err != nil {
		log.Printf("sendFile: %v", err)
	}
}

const configCaption = `📲 *Как подключиться:*
Сохрани файл конфигурации на устройстве и импортируй его в приложение WireGuard:
• *Android / iOS:* WireGuard → «+» → «Импорт из файла» → выбери файл из этого сообщения, 
• *Windows / macOS:* WireGuard → «Add Tunnel» → выбери файл из этого сообщения.

*Важно!* 
1. Не передавай этот файл третьим лицам, он содержит приватный ключ и позволяет подключаться к VPN от имени этого пользователя.
2. По одному файлу конфигурации поддерживается подключение только с одного устройства одновременно. Если подключиться с другого устройства, первое будет отключено.
3. Экономь трафик: при неиспользовании VPN отключай его в приложении WireGuard, а не просто закрывай приложение. Иначе он будет работать в фоне и потреблять трафик, а также мешать работе других приложений.
4. На Android есть возможность указать приложения, для которых будет использоваться VPN. Рекомендуется настроить эту опцию и выбрать только те приложения, которым нужен VPN, чтобы не расходовать трафик и не мешать работе других прилложений.`

func validLogin(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !('a' <= r && r <= 'z') && !('A' <= r && r <= 'Z') &&
			!('0' <= r && r <= '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

const helpText = `*WireGuard VPN Manager*

/adduser [login] — add peer, get client config
/deluser [login] — remove peer
/listusers — list all peers with status
/getconfig [login] — re-send client config
/wgstate — show if WireGuard is running or stopped
/startwg — start WireGuard service
/stopwg — stop WireGuard service
/status — show wg peer details
/cancel — cancel current input`
