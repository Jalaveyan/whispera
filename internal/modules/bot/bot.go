package bot

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/db"
	"whispera/internal/logger"
	"whispera/internal/modules/bridgepool"
	"whispera/internal/modules/config"
	"whispera/pkg/wiraid"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "bot"
	ModuleVersion = "1.0.0"
)

type Bot struct {
	*base.Module
	config     *config.BotConfig
	api        *tgbotapi.BotAPI
	db         *db.DB
	log        *logger.Logger
	bridgePool   *bridgepool.Registry
	wiraidEngine *wiraid.Engine
	mu           sync.Mutex

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func New(cfg interface{}, database *db.DB) (*Bot, error) {
	var conf *config.BotConfig
	if c, ok := cfg.(*config.BotConfig); ok {
		conf = c
	} else {
		conf = &config.BotConfig{}
	}

	b := &Bot{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: conf,
		db:     database,
		log:    logger.Module("bot"),
		stopCh: make(chan struct{}),
	}

	return b, nil
}

func (b *Bot) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := b.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if conf, ok := cfg.(*config.BotConfig); ok {
		b.config = conf
	}

	if b.config.Token == "" {
		return fmt.Errorf("telegram token is required")
	}

	api, err := tgbotapi.NewBotAPI(b.config.Token)
	if err != nil {
		return fmt.Errorf("failed to init telegram bot: %w", err)
	}

	api.Debug = b.config.Debug
	b.api = api

	b.log.Printf("authorized on account %s", api.Self.UserName)
	return nil
}

func (b *Bot) Start() error {
	if err := b.Module.Start(); err != nil {
		return err
	}

	b.wg.Add(1)
	go b.updateLoop()

	go b.notifyStartup()

	b.SetHealthy(true, "bot running")
	return nil
}

func (b *Bot) notifyStartup() {
	time.Sleep(5 * time.Second)

	ip := base.GetPublicIP()
	if ip == "" {
		ip = "unknown"
	}

	msg := fmt.Sprintf("*Whispera Server Started*\n\n"+
		"IP: `%s`\n"+
		"Version: `%s`\n"+
		"Time: `%s`",
		ip, ModuleVersion, time.Now().Format("2006-01-02 15:04:05"))

	b.Broadcast(msg)
}

func (b *Bot) Broadcast(msg string) {
	if b.config.AdminID != 0 {
		m := tgbotapi.NewMessage(b.config.AdminID, msg)
		m.ParseMode = "Markdown"
		b.api.Send(m)
	}

	for _, id := range b.config.MonitorAdminIDs {
		if id != 0 && id != b.config.AdminID {
			m := tgbotapi.NewMessage(id, msg)
			m.ParseMode = "Markdown"
			b.api.Send(m)
		}
	}
}

func (b *Bot) Stop() error {
	close(b.stopCh)
	b.wg.Wait()
	return b.Module.Stop()
}

func (b *Bot) SetWiraidEngine(eng *wiraid.Engine) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.wiraidEngine = eng
}

func (b *Bot) SetBridgePool(bp *bridgepool.Registry) {
	b.bridgePool = bp
}

func (b *Bot) updateLoop() {
	defer b.wg.Done()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := b.api.GetUpdatesChan(u)

	for {
		select {
		case <-b.stopCh:
			return
		case update, ok := <-updates:
			if !ok {
				return
			}
			if update.CallbackQuery != nil {
				b.handleCallback(update.CallbackQuery)
				continue
			}
			if update.Message == nil {
				continue
			}
			b.handleMessage(update.Message)
		}
	}
}

func (b *Bot) isAdmin(userID int64) bool {
	return userID == b.config.AdminID
}

func (b *Bot) isMonitor(userID int64) bool {
	if b.isAdmin(userID) {
		return true
	}
	for _, id := range b.config.MonitorAdminIDs {
		if id == userID {
			return true
		}
	}
	return false
}

func (b *Bot) handleMessage(msg *tgbotapi.Message) {
	if !msg.IsCommand() {
		return
	}

	cmd := msg.Command()
	args := msg.CommandArguments()

	switch cmd {
	case "start":
		b.handleStart(msg)
	case "help":
		b.handleHelp(msg)
	case "me":
		b.handleMe(msg)
	case "id":
		b.reply(msg.Chat.ID, fmt.Sprintf("Your Telegram ID: `%d`", msg.From.ID))
	case "traffic":
		b.handleTraffic(msg)
	case "sessions":
		b.handleSessions(msg)
	case "status":
		b.handleStatus(msg)
	case "users":
		b.handleUsers(msg)
	case "user":
		b.handleUserInfo(msg, args)
	case "kick":
		b.handleKick(msg, args)
	case "ban":
		b.handleBan(msg, args)
	case "unban":
		b.handleUnban(msg, args)
	case "broadcast":
		b.handleBroadcastCmd(msg, args)
	case "restart":
		b.handleRestart(msg, args)
	case "sysinfo":
		b.handleSysinfo(msg)
	case "logs":
		b.handleLogs(msg, args)
	case "bridges":
		b.handleBridges(msg)
	case "bridge":
		b.handleBridgeInfo(msg, args)
	case "bridgescan":
		b.handleBridgeScan(msg)
	case "wiraid_list":
		b.handleWiraidList(msg)
	case "wiraid_install":
		b.handleWiraidInstall(msg, args)
	case "wiraid_uninstall":
		b.handleWiraidUninstall(msg, args)
	case "wiraid_enable":
		b.handleWiraidEnable(msg, args, true)
	case "wiraid_disable":
		b.handleWiraidEnable(msg, args, false)
	default:
		b.reply(msg.Chat.ID, "Unknown command. Use /help")
	}
}

func (b *Bot) reply(chatID int64, text string) {
	m := tgbotapi.NewMessage(chatID, text)
	m.ParseMode = "Markdown"
	b.api.Send(m)
}

func (b *Bot) replyWithKeyboard(chatID int64, text string, keyboard tgbotapi.InlineKeyboardMarkup) {
	m := tgbotapi.NewMessage(chatID, text)
	m.ParseMode = "Markdown"
	m.ReplyMarkup = keyboard
	b.api.Send(m)
}

func (b *Bot) handleStart(msg *tgbotapi.Message) {
	txt := "*Welcome to Whispera Bot*\n\n" +
		"Manage your VPN connection.\n\n" +
		"User commands:\n" +
		"/me — profile and traffic\n" +
		"/traffic — traffic stats (7 days)\n" +
		"/sessions — active sessions\n" +
		"/id — your Telegram ID\n"

	if b.isMonitor(msg.From.ID) {
		txt += "\nMonitor commands:\n" +
			"/status — server status\n" +
			"/users — user list\n" +
			"/sysinfo — system info\n"
	}

	if b.isAdmin(msg.From.ID) {
		txt += "\nAdmin commands:\n" +
			"/user <email> — user details\n" +
			"/kick <email> — disconnect user sessions\n" +
			"/ban <email> — deactivate user\n" +
			"/unban <email> — reactivate user\n" +
			"/broadcast <msg> — send to all monitors\n" +
			"/restart <service> — restart service\n" +
			"/logs [lines] — recent system logs\n" +
			"/bridges — bridge pool overview\n" +
			"/bridge <id> — bridge details & health check\n" +
			"/bridgescan — scan all bridges now\n"
	}

	b.reply(msg.Chat.ID, txt)
}

func (b *Bot) handleHelp(msg *tgbotapi.Message) {
	b.handleStart(msg)
}

func (b *Bot) handleMe(msg *tgbotapi.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := b.db.GetUserByTelegramID(ctx, msg.From.ID)
	if err != nil {
		b.reply(msg.Chat.ID, fmt.Sprintf("Not registered.\nYour Telegram ID: `%d`", msg.From.ID))
		return
	}

	gbUsed := float64(user.TrafficUsed) / 1073741824
	gbLimit := float64(user.TrafficLimit) / 1073741824

	pct := float64(0)
	if user.TrafficLimit > 0 {
		pct = float64(user.TrafficUsed) / float64(user.TrafficLimit) * 100
	}
	bar := progressBar(pct, 10)

	txt := fmt.Sprintf("*Profile*: `%s`\n", user.Email)
	txt += fmt.Sprintf("Plan: `%s`\n", user.PlanName)
	txt += fmt.Sprintf("Traffic: %.2f / %.2f GB\n", gbUsed, gbLimit)
	txt += fmt.Sprintf("%s %.0f%%\n", bar, pct)
	txt += fmt.Sprintf("Devices: max %d\n", user.MaxDevices)
	txt += fmt.Sprintf("Status: %s\n", boolStatus(user.IsActive))

	if user.ValidUntil != nil {
		days := int(time.Until(*user.ValidUntil).Hours() / 24)
		txt += fmt.Sprintf("Expires: %s (%d days)\n", user.ValidUntil.Format("2006-01-02"), days)
	}

	sessions, _ := b.db.CountUserSessions(ctx, user.ID)
	txt += fmt.Sprintf("Active sessions: %d\n", sessions)

	b.reply(msg.Chat.ID, txt)
}

func (b *Bot) handleTraffic(msg *tgbotapi.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := b.db.GetUserByTelegramID(ctx, msg.From.ID)
	if err != nil {
		b.reply(msg.Chat.ID, "Not registered.")
		return
	}

	stats, err := b.db.GetUserDailyStats(ctx, user.ID, 7)
	if err != nil || len(stats) == 0 {
		b.reply(msg.Chat.ID, "No traffic data yet.")
		return
	}

	txt := "*Traffic (7 days)*\n\n"
	for _, s := range stats {
		inMB := float64(s.BytesIn) / 1048576
		outMB := float64(s.BytesOut) / 1048576
		txt += fmt.Sprintf("`%s` IN: %.1f MB | OUT: %.1f MB | %d sess\n",
			s.Date.Format("01-02"), inMB, outMB, s.Sessions)
	}

	total, _ := b.db.GetUserTotalStats(ctx, user.ID)
	if total != nil {
		txt += fmt.Sprintf("\nTotal: IN %.2f GB | OUT %.2f GB\n",
			float64(total.TotalBytesIn)/1073741824,
			float64(total.TotalBytesOut)/1073741824)
	}

	b.reply(msg.Chat.ID, txt)
}

func (b *Bot) handleSessions(msg *tgbotapi.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := b.db.GetUserByTelegramID(ctx, msg.From.ID)
	if err != nil {
		b.reply(msg.Chat.ID, "Not registered.")
		return
	}

	sessions, err := b.db.GetUserSessions(ctx, user.ID)
	if err != nil || len(sessions) == 0 {
		b.reply(msg.Chat.ID, "No active sessions.")
		return
	}

	txt := fmt.Sprintf("*Active sessions* (%d)\n\n", len(sessions))
	for i, s := range sessions {
		dur := time.Since(s.StartedAt).Truncate(time.Minute)
		txt += fmt.Sprintf("%d. `%s` | %s | %s | IN %.1f MB | OUT %.1f MB\n",
			i+1, s.DeviceName, s.IPAddress, dur,
			float64(s.BytesIn)/1048576, float64(s.BytesOut)/1048576)
	}

	b.reply(msg.Chat.ID, txt)
}

func (b *Bot) handleStatus(msg *tgbotapi.Message) {
	if !b.isMonitor(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip := base.GetPublicIP()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	users, _ := b.db.ListUsers(ctx, 1000, 0)
	activeCount := 0
	for _, u := range users {
		if u.IsActive {
			activeCount++
		}
	}

	var totalSessions int
	for _, u := range users {
		c, _ := b.db.CountUserSessions(ctx, u.ID)
		totalSessions += c
	}

	txt := "*Server Status*\n\n"
	txt += fmt.Sprintf("IP: `%s`\n", ip)
	txt += fmt.Sprintf("Uptime: %s\n", uptime())
	txt += fmt.Sprintf("Memory: %.1f MB (alloc) / %.1f MB (sys)\n",
		float64(m.Alloc)/1048576, float64(m.Sys)/1048576)
	txt += fmt.Sprintf("Goroutines: %d\n", runtime.NumGoroutine())
	txt += fmt.Sprintf("Users: %d total, %d active\n", len(users), activeCount)
	txt += fmt.Sprintf("Sessions: %d active\n", totalSessions)
	txt += fmt.Sprintf("Go: %s\n", runtime.Version())

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Refresh", "status_refresh"),
		),
	)

	b.replyWithKeyboard(msg.Chat.ID, txt, keyboard)
}

func (b *Bot) handleUsers(msg *tgbotapi.Message) {
	if !b.isMonitor(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	users, err := b.db.ListUsers(ctx, 50, 0)
	if err != nil {
		b.reply(msg.Chat.ID, "Failed to load users.")
		return
	}

	if len(users) == 0 {
		b.reply(msg.Chat.ID, "No users.")
		return
	}

	txt := fmt.Sprintf("*Users* (%d)\n\n", len(users))
	for i, u := range users {
		gb := float64(u.TrafficUsed) / 1073741824
		status := "ON"
		if !u.IsActive {
			status = "OFF"
		}
		sessions, _ := b.db.CountUserSessions(ctx, u.ID)
		txt += fmt.Sprintf("%d. `%s` [%s] %.2f GB | %d sess",
			i+1, u.Email, status, gb, sessions)
		if u.IsAdmin {
			txt += " | admin"
		}
		txt += "\n"
		if len(txt) > 3500 {
			txt += fmt.Sprintf("\n... and %d more", len(users)-i-1)
			break
		}
	}

	b.reply(msg.Chat.ID, txt)
}

func (b *Bot) handleUserInfo(msg *tgbotapi.Message, args string) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	email := strings.TrimSpace(args)
	if email == "" {
		b.reply(msg.Chat.ID, "Usage: /user <email>")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := b.db.GetUserByEmail(ctx, email)
	if err != nil {
		b.reply(msg.Chat.ID, fmt.Sprintf("User `%s` not found.", email))
		return
	}

	gbUsed := float64(user.TrafficUsed) / 1073741824
	gbLimit := float64(user.TrafficLimit) / 1073741824

	txt := fmt.Sprintf("*User*: `%s`\n", user.Email)
	txt += fmt.Sprintf("ID: `%s`\n", user.ID)
	txt += fmt.Sprintf("Plan: `%s`\n", user.PlanName)
	txt += fmt.Sprintf("Status: %s | Admin: %s\n", boolStatus(user.IsActive), boolYesNo(user.IsAdmin))
	txt += fmt.Sprintf("Traffic: %.2f / %.2f GB\n", gbUsed, gbLimit)
	txt += fmt.Sprintf("Devices: max %d\n", user.MaxDevices)
	txt += fmt.Sprintf("Obfs: `%s` | Marionette: `%s`\n", user.ObfsProfile, user.MarionetteProfile)
	txt += fmt.Sprintf("Service: `%s`\n", user.RussianService)

	if user.TelegramID != nil {
		txt += fmt.Sprintf("Telegram: `%d`\n", *user.TelegramID)
	}
	if user.ValidUntil != nil {
		txt += fmt.Sprintf("Expires: %s\n", user.ValidUntil.Format("2006-01-02"))
	}
	txt += fmt.Sprintf("Created: %s\n", user.CreatedAt.Format("2006-01-02 15:04"))

	sessions, _ := b.db.GetUserSessions(ctx, user.ID)
	txt += fmt.Sprintf("Sessions: %d active\n", len(sessions))
	for _, s := range sessions {
		txt += fmt.Sprintf("  - `%s` %s %s\n", s.DeviceName, s.IPAddress,
			time.Since(s.StartedAt).Truncate(time.Minute))
	}

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Kick", "kick_"+user.Email),
			tgbotapi.NewInlineKeyboardButtonData("Ban", "ban_"+user.Email),
		),
	)

	b.replyWithKeyboard(msg.Chat.ID, txt, keyboard)
}

func (b *Bot) handleKick(msg *tgbotapi.Message, args string) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	email := strings.TrimSpace(args)
	if email == "" {
		b.reply(msg.Chat.ID, "Usage: /kick <email>")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := b.db.GetUserByEmail(ctx, email)
	if err != nil {
		b.reply(msg.Chat.ID, "User not found.")
		return
	}

	err = b.db.DeleteUserSessions(ctx, user.ID)
	if err != nil {
		b.reply(msg.Chat.ID, "Failed to kick user.")
		return
	}

	b.reply(msg.Chat.ID, fmt.Sprintf("All sessions for `%s` terminated.", email))
}

func (b *Bot) handleBan(msg *tgbotapi.Message, args string) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	email := strings.TrimSpace(args)
	if email == "" {
		b.reply(msg.Chat.ID, "Usage: /ban <email>")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := b.db.GetUserByEmail(ctx, email)
	if err != nil {
		b.reply(msg.Chat.ID, "User not found.")
		return
	}

	if user.IsAdmin {
		b.reply(msg.Chat.ID, "Cannot ban admin.")
		return
	}

	_ = b.db.DeleteUserSessions(ctx, user.ID)

	active := false
	_ = b.db.SetUserActive(ctx, user.ID, active)

	b.reply(msg.Chat.ID, fmt.Sprintf("User `%s` banned and sessions terminated.", email))
}

func (b *Bot) handleUnban(msg *tgbotapi.Message, args string) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	email := strings.TrimSpace(args)
	if email == "" {
		b.reply(msg.Chat.ID, "Usage: /unban <email>")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := b.db.GetUserByEmail(ctx, email)
	if err != nil {
		b.reply(msg.Chat.ID, "User not found.")
		return
	}

	_ = b.db.SetUserActive(ctx, user.ID, true)

	b.reply(msg.Chat.ID, fmt.Sprintf("User `%s` unbanned.", email))
}

func (b *Bot) handleBroadcastCmd(msg *tgbotapi.Message, args string) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	text := strings.TrimSpace(args)
	if text == "" {
		b.reply(msg.Chat.ID, "Usage: /broadcast <message>")
		return
	}

	b.Broadcast(fmt.Sprintf("*Broadcast*\n\n%s", text))
	b.reply(msg.Chat.ID, "Broadcast sent.")
}

func (b *Bot) handleRestart(msg *tgbotapi.Message, args string) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	service := strings.TrimSpace(args)
	allowed := map[string]bool{
		"whispera":       true,
		"whispera-panel": true,
		"whispera-ml":    true,
	}

	if service == "" || !allowed[service] {
		b.reply(msg.Chat.ID, "Usage: /restart <whispera|whispera-panel|whispera-ml>")
		return
	}

	b.reply(msg.Chat.ID, fmt.Sprintf("Restarting `%s`...", service))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "systemctl", "restart", service)
		out, err := cmd.CombinedOutput()
		if err != nil {
			b.reply(msg.Chat.ID, fmt.Sprintf("Restart failed: %s\n`%s`", err, string(out)))
			return
		}
		b.reply(msg.Chat.ID, fmt.Sprintf("`%s` restarted.", service))
	}()
}

func (b *Bot) handleSysinfo(msg *tgbotapi.Message) {
	if !b.isMonitor(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var lines []string

	if out, err := exec.CommandContext(ctx, "uptime").Output(); err == nil {
		lines = append(lines, fmt.Sprintf("Uptime: `%s`", strings.TrimSpace(string(out))))
	}

	if out, err := exec.CommandContext(ctx, "free", "-h").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Mem:") {
				lines = append(lines, fmt.Sprintf("Memory: `%s`", strings.TrimSpace(line)))
			}
		}
	}

	if out, err := exec.CommandContext(ctx, "df", "-h", "/").Output(); err == nil {
		parts := strings.Split(string(out), "\n")
		if len(parts) > 1 {
			lines = append(lines, fmt.Sprintf("Disk: `%s`", strings.TrimSpace(parts[1])))
		}
	}

	if out, err := exec.CommandContext(ctx, "cat", "/proc/loadavg").Output(); err == nil {
		lines = append(lines, fmt.Sprintf("Load: `%s`", strings.TrimSpace(string(out))))
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	lines = append(lines, fmt.Sprintf("Go heap: `%.1f MB`", float64(m.Alloc)/1048576))
	lines = append(lines, fmt.Sprintf("Goroutines: `%d`", runtime.NumGoroutine()))

	if len(lines) == 0 {
		b.reply(msg.Chat.ID, "Failed to collect system info.")
		return
	}

	b.reply(msg.Chat.ID, "*System Info*\n\n"+strings.Join(lines, "\n"))
}

func (b *Bot) handleLogs(msg *tgbotapi.Message, args string) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}

	n := "20"
	if a := strings.TrimSpace(args); a != "" {
		n = a
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "journalctl", "-u", "whispera", "-n", n, "--no-pager").Output()
	if err != nil {
		b.reply(msg.Chat.ID, "Failed to read logs.")
		return
	}

	text := string(out)
	if len(text) > 3900 {
		text = text[len(text)-3900:]
	}

	b.reply(msg.Chat.ID, fmt.Sprintf("*Logs (last %s)*\n\n```\n%s\n```", n, text))
}

func (b *Bot) handleBridges(msg *tgbotapi.Message) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}
	if b.bridgePool == nil {
		b.reply(msg.Chat.ID, "Bridge pool not available.")
		return
	}

	stats := b.bridgePool.BridgeStats()
	all := b.bridgePool.GetAllBridges()

	txt := fmt.Sprintf("*Bridge Pool*\n\nTotal: %v | Alive: %v | Dead: %v | Avg latency: %vms\n\n",
		stats["total"], stats["alive"], stats["dead"], stats["avg_latency"])

	for i, br := range all {
		status := "DEAD"
		if br.IsAlive {
			status = "OK"
		}
		name := br.ID
		if br.Name != "" {
			name = br.Name
		}
		region := br.Region
		if br.Country != "" {
			region = br.Country
		}
		if region == "" {
			region = "-"
		}
		txt += fmt.Sprintf("%d. `%s` [%s] %s %dms load=%.0f%% %d/%d users\n",
			i+1, name, status, region, br.Latency,
			br.Load*100, br.CurUsers, br.MaxUsers)
		if len(txt) > 3500 {
			txt += fmt.Sprintf("\n... and %d more", len(all)-i-1)
			break
		}
	}

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Refresh", "bridges_refresh"),
			tgbotapi.NewInlineKeyboardButtonData("Scan All", "bridges_scan"),
		),
	)
	b.replyWithKeyboard(msg.Chat.ID, txt, keyboard)
}

func (b *Bot) handleBridgeInfo(msg *tgbotapi.Message, args string) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}
	if b.bridgePool == nil {
		b.reply(msg.Chat.ID, "Bridge pool not available.")
		return
	}

	id := strings.TrimSpace(args)
	if id == "" {
		b.reply(msg.Chat.ID, "Usage: /bridge <id>")
		return
	}

	br, err := b.bridgePool.GetBridge(id)
	if err != nil {
		b.reply(msg.Chat.ID, fmt.Sprintf("Bridge `%s` not found.", id))
		return
	}

	status := "DEAD"
	if br.IsAlive {
		status = "ALIVE"
	}

	txt := fmt.Sprintf("*Bridge*: `%s`\n", br.ID)
	if br.Name != "" {
		txt += fmt.Sprintf("Name: `%s`\n", br.Name)
	}
	txt += fmt.Sprintf("Address: `%s`\n", br.Address)
	txt += fmt.Sprintf("Type: `%s`\n", br.Type)
	txt += fmt.Sprintf("Status: %s | Latency: %dms\n", status, br.Latency)
	txt += fmt.Sprintf("Load: %.0f%% | Users: %d/%d\n", br.Load*100, br.CurUsers, br.MaxUsers)
	txt += fmt.Sprintf("Trust: %d | Loss: %.1f%%\n", br.TrustLevel, br.LossPct)
	if br.Region != "" {
		txt += fmt.Sprintf("Region: %s\n", br.Region)
	}
	if br.Country != "" {
		txt += fmt.Sprintf("Location: %s %s\n", br.Country, br.City)
	}
	if br.Provider != "" {
		txt += fmt.Sprintf("Provider: %s\n", br.Provider)
	}
	if br.Version != "" {
		txt += fmt.Sprintf("Version: `%s`\n", br.Version)
	}
	if br.Blacklisted {
		txt += "Blacklisted: YES\n"
	}
	txt += fmt.Sprintf("Last check: %s\n", br.LastCheck.Format("2006-01-02 15:04:05"))
	txt += fmt.Sprintf("Created: %s\n", br.CreatedAt.Format("2006-01-02"))

	isAlive, latency, checkErr := b.bridgePool.CheckBridgeNow(id)
	if checkErr == nil {
		checkStatus := "DEAD"
		if isAlive {
			checkStatus = "ALIVE"
		}
		txt += fmt.Sprintf("\nLive check: %s (%dms)\n", checkStatus, latency)
	}

	keys := b.bridgePool.GetAccessKeysForBridge(id)
	if len(keys) > 0 {
		txt += fmt.Sprintf("Access keys: %d\n", len(keys))
	}

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Check Now", "bridge_check_"+id),
			tgbotapi.NewInlineKeyboardButtonData("Blacklist", "bridge_bl_"+id),
		),
	)
	b.replyWithKeyboard(msg.Chat.ID, txt, keyboard)
}

func (b *Bot) handleBridgeScan(msg *tgbotapi.Message) {
	if !b.isAdmin(msg.From.ID) {
		b.reply(msg.Chat.ID, "Access denied.")
		return
	}
	if b.bridgePool == nil {
		b.reply(msg.Chat.ID, "Bridge pool not available.")
		return
	}

	b.reply(msg.Chat.ID, "Scanning all bridges...")

	go func() {
		results := b.bridgePool.ScanAllBridges()
		alive := 0
		for _, r := range results {
			if a, ok := r["is_alive"].(bool); ok && a {
				alive++
			}
		}

		txt := fmt.Sprintf("*Scan complete*\n\nTotal: %d | Alive: %d | Dead: %d\n\n",
			len(results), alive, len(results)-alive)

		for i, r := range results {
			id, _ := r["id"].(string)
			isAlive, _ := r["is_alive"].(bool)
			latency, _ := r["latency"].(int)
			status := "DEAD"
			if isAlive {
				status = "OK"
			}
			txt += fmt.Sprintf("`%s` [%s] %dms\n", id, status, latency)
			if len(txt) > 3500 {
				txt += fmt.Sprintf("\n... and %d more", len(results)-i-1)
				break
			}
		}

		b.reply(msg.Chat.ID, txt)
	}()
}

func (b *Bot) handleCallback(cb *tgbotapi.CallbackQuery) {
	ack := tgbotapi.NewCallback(cb.ID, "")
	_, _ = b.api.Request(ack)

	data := cb.Data

	switch {
	case data == "status_refresh":
		if !b.isMonitor(cb.From.ID) {
			return
		}
		fakeMsg := &tgbotapi.Message{
			Chat: cb.Message.Chat,
			From: cb.From,
		}
		b.handleStatus(fakeMsg)

	case strings.HasPrefix(data, "kick_"):
		if !b.isAdmin(cb.From.ID) {
			return
		}
		email := strings.TrimPrefix(data, "kick_")
		fakeMsg := &tgbotapi.Message{
			Chat: cb.Message.Chat,
			From: cb.From,
		}
		b.handleKick(fakeMsg, email)

	case strings.HasPrefix(data, "ban_"):
		if !b.isAdmin(cb.From.ID) {
			return
		}
		email := strings.TrimPrefix(data, "ban_")
		fakeMsg := &tgbotapi.Message{
			Chat: cb.Message.Chat,
			From: cb.From,
		}
		b.handleBan(fakeMsg, email)

	case data == "bridges_refresh":
		if !b.isAdmin(cb.From.ID) {
			return
		}
		fakeMsg := &tgbotapi.Message{Chat: cb.Message.Chat, From: cb.From}
		b.handleBridges(fakeMsg)

	case data == "bridges_scan":
		if !b.isAdmin(cb.From.ID) {
			return
		}
		fakeMsg := &tgbotapi.Message{Chat: cb.Message.Chat, From: cb.From}
		b.handleBridgeScan(fakeMsg)

	case strings.HasPrefix(data, "bridge_check_"):
		if !b.isAdmin(cb.From.ID) {
			return
		}
		id := strings.TrimPrefix(data, "bridge_check_")
		fakeMsg := &tgbotapi.Message{Chat: cb.Message.Chat, From: cb.From}
		b.handleBridgeInfo(fakeMsg, id)

	case strings.HasPrefix(data, "bridge_bl_"):
		if !b.isAdmin(cb.From.ID) {
			return
		}
		id := strings.TrimPrefix(data, "bridge_bl_")
		if b.bridgePool != nil {
			if err := b.bridgePool.SetBridgeLabel(id, true); err != nil {
				b.reply(cb.Message.Chat.ID, fmt.Sprintf("Failed: %v", err))
			} else {
				b.reply(cb.Message.Chat.ID, fmt.Sprintf("Bridge `%s` blacklisted.", id))
			}
		}
	}
}

func progressBar(pct float64, width int) string {
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	return "[" + strings.Repeat("=", filled) + strings.Repeat("-", width-filled) + "]"
}

func boolStatus(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

var startTime = time.Now()

func uptime() string {
	d := time.Since(startTime)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 24 {
		return fmt.Sprintf("%dd %dh %dm", h/24, h%24, m)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	return New(cfg, db.Global())
}

func (b *Bot) handleWiraidList(msg *tgbotapi.Message) {
	if b.wiraidEngine == nil {
		b.reply(msg.Chat.ID, "WIRAID engine not initialized")
		return
	}
	mods := b.wiraidEngine.Summaries()
	if len(mods) == 0 {
		b.reply(msg.Chat.ID, "No WIRAID modules installed")
		return
	}
	var sb strings.Builder
	sb.WriteString("*WIRAID modules:*\n")
	for _, m := range mods {
		state := "off"
		if m.Running {
			state = fmt.Sprintf("running:%d", m.Port)
		} else if m.Enabled {
			state = "enabled"
		}
		sb.WriteString(fmt.Sprintf("• `%s` v%s [%s] — %s\n", m.Name, m.Version, m.Lang, state))
	}
	b.reply(msg.Chat.ID, sb.String())
}

func (b *Bot) handleWiraidInstall(msg *tgbotapi.Message, args string) {
	if b.wiraidEngine == nil {
		b.reply(msg.Chat.ID, "WIRAID engine not initialized")
		return
	}
	url := strings.TrimSpace(args)
	if url == "" {
		b.reply(msg.Chat.ID, "Usage: /wiraid_install <url>")
		return
	}
	b.reply(msg.Chat.ID, "Installing... this may take a minute")
	go func() {
		name, err := b.wiraidEngine.InstallFromURL(url)
		if err != nil {
			b.reply(msg.Chat.ID, fmt.Sprintf("Install failed:\n```\n%s\n```", err.Error()))
			return
		}
		b.reply(msg.Chat.ID, fmt.Sprintf("Installed: `%s`", name))
	}()
}

func (b *Bot) handleWiraidUninstall(msg *tgbotapi.Message, args string) {
	if b.wiraidEngine == nil {
		b.reply(msg.Chat.ID, "WIRAID engine not initialized")
		return
	}
	name := strings.TrimSpace(args)
	if name == "" {
		b.reply(msg.Chat.ID, "Usage: /wiraid_uninstall <name>")
		return
	}
	if err := b.wiraidEngine.Uninstall(name); err != nil {
		b.reply(msg.Chat.ID, fmt.Sprintf("Uninstall failed: %v", err))
		return
	}
	b.reply(msg.Chat.ID, fmt.Sprintf("Removed: `%s`", name))
}

func (b *Bot) handleWiraidEnable(msg *tgbotapi.Message, args string, enabled bool) {
	if b.wiraidEngine == nil {
		b.reply(msg.Chat.ID, "WIRAID engine not initialized")
		return
	}
	name := strings.TrimSpace(args)
	if name == "" {
		verb := "enable"
		if !enabled {
			verb = "disable"
		}
		b.reply(msg.Chat.ID, fmt.Sprintf("Usage: /wiraid_%s <name>", verb))
		return
	}
	if err := b.wiraidEngine.Registry.SetEnabled(name, enabled); err != nil {
		b.reply(msg.Chat.ID, fmt.Sprintf("Failed: %v", err))
		return
	}
	state := "enabled"
	if !enabled {
		state = "disabled"
	}
	b.reply(msg.Chat.ID, fmt.Sprintf("`%s` %s", name, state))
}
