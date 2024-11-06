package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"dawnchann/constant"
	"dawnchann/request"
	"encoding/json"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	browser "github.com/itzngga/fake-useragent"
	"github.com/joho/godotenv"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"time"
)

var logger *zap.Logger

type Account struct {
	Auth    request.Authentication
	Proxies []string
}

type ProxyConfig struct {
	URL      string
	Username string
	Password string
	Protocol string
}

type ProxyDistributor struct {
	userIDs []string
	proxies []string
	logger  *zap.Logger
	mu      sync.Mutex
}

func (pd *ProxyDistributor) Validate() error {
	if len(pd.userIDs) == 0 || len(pd.proxies) == 0 {
		return fmt.Errorf("no user IDs or proxies found")
	}

	if len(pd.userIDs) > len(pd.proxies) {
		return fmt.Errorf("number of user IDs (%d) cannot be greater than number of proxies (%d)",
			len(pd.userIDs), len(pd.proxies))
	}

	return nil
}

func (pd *ProxyDistributor) DistributeProxies() map[string][]string {
	distribution := make(map[string][]string)
	baseProxiesPerUser := len(pd.proxies) / len(pd.userIDs)
	remainingProxies := len(pd.proxies) % len(pd.userIDs)

	currentIndex := 0
	for i, userID := range pd.userIDs {
		proxiesForThisUser := baseProxiesPerUser
		if i == 0 {
			proxiesForThisUser += remainingProxies
		}

		distribution[userID] = pd.proxies[currentIndex : currentIndex+proxiesForThisUser]
		currentIndex += proxiesForThisUser

		pd.logger.Info("Distributed proxies for user",
			zap.String("userID", userID),
			zap.Int("proxyCount", len(distribution[userID])))
	}

	return distribution
}

func NewProxyDistributor(userIDs, proxies []string, logger *zap.Logger) *ProxyDistributor {
	return &ProxyDistributor{
		userIDs: userIDs,
		proxies: proxies,
		logger:  logger,
	}
}

func parseLoginFile(path string) ([]string, []request.Authentication, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var userIDs []string
	var auths []request.Authentication
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			logger.Warn("Skipping invalid login line", zap.String("line", line))
			continue
		}

		email := strings.TrimSpace(parts[0])
		userIDs = append(userIDs, email)
		auths = append(auths, request.Authentication{
			Email:    email,
			Password: strings.TrimSpace(parts[1]),
		})
	}

	return userIDs, auths, scanner.Err()
}

func parseProxyLine(line string) (*ProxyConfig, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty proxy line")
	}

	proxy := &ProxyConfig{}

	if strings.Contains(line, "://") {
		parts := strings.SplitN(line, "://", 2)
		proxy.Protocol = parts[0]
		line = parts[1]
	} else {
		proxy.Protocol = "http"
	}

	proxy.Protocol = strings.ToLower(proxy.Protocol)
	if proxy.Protocol != "http" && proxy.Protocol != "https" && proxy.Protocol != "socks5" {
		return nil, fmt.Errorf("unsupported proxy protocol: %s", proxy.Protocol)
	}

	if strings.Contains(line, "@") {
		authParts := strings.SplitN(line, "@", 2)
		credentials := strings.SplitN(authParts[0], ":", 2)
		if len(credentials) != 2 {
			return nil, fmt.Errorf("invalid proxy credentials format")
		}
		proxy.Username = credentials[0]
		proxy.Password = credentials[1]
		line = authParts[1]
	}

	if proxy.Username != "" && proxy.Password != "" {
		proxy.URL = fmt.Sprintf("%s://%s:%s@%s", proxy.Protocol, proxy.Username, proxy.Password, line)
	} else {
		proxy.URL = fmt.Sprintf("%s://%s", proxy.Protocol, line)
	}

	return proxy, nil
}

func readProxies(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		proxy, err := parseProxyLine(line)
		if err != nil {
			logger.Warn("Skipping invalid proxy line", zap.String("line", line), zap.Error(err))
			continue
		}
		proxies = append(proxies, proxy.URL)
	}

	return proxies, scanner.Err()
}

func calculateTotalPoints(jsonResponse string) (float64, error) {
	var response request.PointResponse
	err := json.Unmarshal([]byte(jsonResponse), &response)
	if err != nil {
		return 0, fmt.Errorf("error parsing JSON: %v", err)
	}

	if !response.Status {
		return 0, fmt.Errorf("error fetching points: %s", response.Message)
	}

	totalPoints := response.Data.RewardPoint.Points +
		response.Data.RewardPoint.RegisterPoints +
		response.Data.RewardPoint.SignInPoints +
		response.Data.RewardPoint.TwitterXIDPoints +
		response.Data.RewardPoint.DiscordIDPoints +
		response.Data.RewardPoint.TelegramIDPoints +
		response.Data.RewardPoint.BonusPoints +
		response.Data.ReferralPoint.Commission

	return totalPoints, nil
}

func cleanResponse(response string) string {
	if strings.Contains(response, "502 Bad Gateway") {
		return ""
	}
	return response
}

func formatReadablePoints(points float64) string {
	if points == 0 {
		return "0"
	}
	points = math.Round(points*100) / 100

	if points >= 1000 {
		return fmt.Sprintf("%s", humanizeFloat(points))
	}

	return fmt.Sprintf("%.2f", points)
}

func humanizeFloat(f float64) string {
	intPart, fracPart := math.Modf(f)
	intStr := fmt.Sprintf("%d", int(intPart))

	for i := len(intStr) - 3; i > 0; i -= 3 {
		intStr = intStr[:i] + "," + intStr[i:]
	}

	if fracPart == 0 {
		return intStr
	}

	return fmt.Sprintf("%s.%03d", intStr, int(fracPart*1000))
}

func ping(account Account, userAgent string) {
	currentProxyIndex := 0
	for {
		proxy := account.Proxies[currentProxyIndex]
		currentProxyIndex = (currentProxyIndex + 1) % len(account.Proxies)

		client := resty.New().SetProxy(proxy).
			SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
			SetHeader("content-type", "application/json").
			SetHeader("origin", "chrome-extension://fpdkjdnhkakefebpekbdhillbhonfjjp").
			SetHeader("accept", "*/*").
			SetHeader("accept-language", "en-US,en;q=0.9").
			SetHeader("priority", "u=1, i").
			SetHeader("sec-fetch-dest", "empty").
			SetHeader("sec-fetch-mode", "cors").
			SetHeader("sec-fetch-site", "cross-site").
			SetHeader("user-agent", userAgent)

		keepAliveRequest := map[string]interface{}{
			"username":     account.Auth.Email,
			"extensionid":  "fpdkjdnhkakefebpekbdhillbhonfjjp",
			"numberoftabs": 0,
			"_v":           "1.0.7",
		}

		res, err := client.R().
			SetHeader("authorization", fmt.Sprintf("Bearer %v", account.Auth.Password)).
			SetBody(keepAliveRequest).
			Post(constant.KeepAliveURL)
		if err != nil {
			logger.Error("Keep alive error",
				zap.String("acc", account.Auth.Email),
				zap.Error(err))
		} else {
			logger.Info("Keep alive success",
				zap.String("acc", account.Auth.Email),
				zap.String("res", cleanResponse(res.String())))
		}

		res, err = client.R().
			SetHeader("authorization", fmt.Sprintf("Bearer %v", account.Auth.Password)).
			Get(constant.GetPointURL)
		if err != nil {
			logger.Error("Get point error",
				zap.String("acc", account.Auth.Email),
				zap.Error(err))
		} else {
			points, err := calculateTotalPoints(res.String())
			if err != nil {
				logger.Error("Error calculating points",
					zap.String("acc", account.Auth.Email),
					zap.Error(err))
			} else {
				logger.Info("Points calculated",
					zap.String("acc", account.Auth.Email),
					zap.String("points", formatReadablePoints(points)))
			}
		}

		time.Sleep(1 * time.Minute)
	}
}

// telegram logic
func logUserInteraction(update *models.Update, action string) {
	username := update.Message.From.Username
	if username == "" {
		username = fmt.Sprintf("%s %s", update.Message.From.FirstName, update.Message.From.LastName)
	}
	log.Printf("User %s %s", username, action)
}

func handleStart(ctx context.Context, b *bot.Bot, update *models.Update) {
	logUserInteraction(update, "started the bot")
	if _, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Welcome, please send the /point command to check your points",
	}); err != nil {
		log.Printf("Error sending message: %v", err)
	}
}

func handlePoint(ctx context.Context, b *bot.Bot, update *models.Update, accounts []Account) {
	logUserInteraction(update, "requested point information")
	sendTelegramNotification(ctx, b, update.Message.Chat.ID, accounts)
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email //return original email
	}

	username := parts[0]
	domain := parts[1]

	//if username is too short, just mask half of it
	if len(username) <= 3 {
		return username[:1] + "***@" + domain
	}

	//keep first 2 and last 2 chars of username, mask the rest
	visibleStart := 2
	visibleEnd := 2
	maskLength := len(username) - (visibleStart + visibleEnd)

	if maskLength < 1 {
		maskLength = 1
	}

	maskedUsername := username[:visibleStart] +
		strings.Repeat("*", maskLength) +
		username[len(username)-visibleEnd:]

	return maskedUsername + "@" + domain
}

func sendTelegramNotification(ctx context.Context, b *bot.Bot, chatID int64, accounts []Account) {
	var messageLines []string
	var totalUsers, successCount int
	var totalPoints float64

	totalUsers = len(accounts)
	messageLines = append(messageLines, fmt.Sprintf("🔍 Dawn Points Checker Report"))
	messageLines = append(messageLines, fmt.Sprintf("📊 Total Accounts: %d\n", totalUsers))

	for i, account := range accounts {
		// Use masked email in the output
		linePrefix := fmt.Sprintf("%d. %s", i+1, maskEmail(account.Auth.Email))

		client := resty.New().
			SetTimeout(30 * time.Second).
			SetRetryCount(3).
			SetRetryWaitTime(5 * time.Second).
			SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
			SetHeaders(map[string]string{
				"content-type":    "application/json",
				"origin":          "chrome-extension://fpdkjdnhkakefebpekbdhillbhonfjjp",
				"accept":          "*/*",
				"accept-language": "en-US,en;q=0.9",
				"priority":        "u=1, i",
				"sec-fetch-dest":  "empty",
				"sec-fetch-mode":  "cors",
				"sec-fetch-site":  "cross-site",
				"user-agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36",
			})

		client.SetProxy(account.Proxies[0])

		res, err := client.R().
			SetHeader("authorization", fmt.Sprintf("Bearer %v", account.Auth.Password)).
			Get(constant.GetPointURL)

		if err != nil {
			logger.Error("Failed to fetch points",
				zap.String("account", maskEmail(account.Auth.Email)),
				zap.Error(err))

			messageLines = append(messageLines, fmt.Sprintf("%s\n❌ Error: Connection failed\n",
				linePrefix))
			continue
		}

		points, err := calculateTotalPoints(res.String())
		if err != nil {
			logger.Error("Failed to calculate points",
				zap.String("account", maskEmail(account.Auth.Email)),
				zap.String("response", cleanResponse(res.String())),
				zap.Error(err))

			messageLines = append(messageLines, fmt.Sprintf("%s\n❌ Error: Invalid response\n", linePrefix))
			continue
		}

		successCount++
		totalPoints += points

		messageLines = append(messageLines, fmt.Sprintf("%s\n Points: %s\n",
			linePrefix,
			formatReadablePoints(points)))
	}

	if successCount > 0 {
		avgPoints := totalPoints / float64(successCount)
		messageLines = append(messageLines, "\n📈 Summary:")
		messageLines = append(messageLines, fmt.Sprintf("• Success Rate: %d/%d (%.1f%%)",
			successCount, totalUsers, float64(successCount)/float64(totalUsers)*100))
		messageLines = append(messageLines, fmt.Sprintf("• Average Points: %s", formatReadablePoints(avgPoints)))
		messageLines = append(messageLines, fmt.Sprintf("• Total Points: %s", formatReadablePoints(totalPoints)))
	}

	jakartaTime, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		logger.Error("Failed to load Jakarta timezone", zap.Error(err))
		messageLines = append(messageLines, fmt.Sprintf("\n🕒 %s", time.Now().Format("2006-01-02 15:04:05 MST")))
	} else {
		messageLines = append(messageLines, fmt.Sprintf("\n🕒 %s",
			time.Now().In(jakartaTime).Format("2006-01-02 15:04:05 WIB")))
	}

	message := strings.Join(messageLines, "\n")
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		_, err := b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID:    chatID,
			Text:      message,
			ParseMode: "HTML",
		})

		if err == nil {
			break
		}

		if attempt == maxRetries {
			logger.Error("Failed to send telegram message after retries",
				zap.Int("attempts", attempt),
				zap.Error(err))
		} else {
			logger.Warn("Failed to send telegram message, retrying...",
				zap.Int("attempt", attempt),
				zap.Error(err))
			time.Sleep(time.Second * time.Duration(attempt))
		}
	}
}

func main() {
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger = zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(config),
		zapcore.AddSync(colorable.NewColorableStdout()),
		zapcore.DebugLevel,
	))

	if err := godotenv.Load(); err != nil {
		logger.Fatal("Error loading .env file", zap.Error(err))
	}

	botToken := os.Getenv("BOT_TOKEN")
	if botToken == "" {
		logger.Fatal("BOT_TOKEN not found in .env")
	}

	userIDs, auths, err := parseLoginFile("login.txt")
	if err != nil {
		logger.Fatal("Error parsing login file", zap.Error(err))
	}

	proxies, err := readProxies("proxy.txt")
	if err != nil {
		logger.Fatal("Error reading proxy file", zap.Error(err))
	}

	distributor := NewProxyDistributor(userIDs, proxies, logger)
	if err := distributor.Validate(); err != nil {
		logger.Fatal("Proxy distribution validation failed", zap.Error(err))
	}

	proxyDistribution := distributor.DistributeProxies()

	var accounts []Account
	for i, auth := range auths {
		accounts = append(accounts, Account{
			Auth:    auth,
			Proxies: proxyDistribution[userIDs[i]],
		})
	}

	b, err := bot.New(botToken)
	if err != nil {
		logger.Fatal("Error creating bot", zap.Error(err))
	}

	b.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, handleStart)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/point", bot.MatchTypeExact, func(ctx context.Context, b *bot.Bot, update *models.Update) {
		handlePoint(ctx, b, update, accounts)
	})

	browserRand := browser.Chrome()
	for _, account := range accounts {
		go ping(account, browserRand)
	}

	b.Start(context.Background())
}
