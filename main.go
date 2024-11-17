package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"dawnchann/constant"
	"dawnchann/request"
	"encoding/json"
	"fmt"
	browser "github.com/itzngga/fake-useragent"
	"github.com/joho/godotenv"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

type Account struct {
	Auth       request.Authentication
	Proxies    []string
	Token      string
	LoginProxy string
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

type SessionExpiredError struct {
	Message string
}

func (e *SessionExpiredError) Error() string {
	return e.Message
}

// if we got session expired err
func isSessionExpired(response string) bool {
	if strings.Contains(response, "session expired") ||
		strings.Contains(response, "Please login again") {
		return true
	}
	return false
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

// get puzzle
func getPuzzleID(userAgent string, proxy string) (string, error) {
	client := resty.New().
		SetTimeout(30 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(5 * time.Second).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetProxy(proxy).
		SetHeaders(map[string]string{
			"accept":          "*/*",
			"accept-language": "en-US,en;q=0.9",
			"user-agent":      userAgent,
		})

	resp, err := client.R().
		Get("https://www.aeropres.in/chromeapi/dawn/v1/puzzle/get-puzzle?appid=undefined")

	if err != nil {
		return "", fmt.Errorf("failed to get puzzle: %v", err)
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	var puzzleResp request.PuzzleResponse
	if err := json.Unmarshal(resp.Body(), &puzzleResp); err != nil {
		return "", fmt.Errorf("failed to parse puzzle response: %v", err)
	}

	if !puzzleResp.Success {
		return "", fmt.Errorf("puzzle request unsuccessful")
	}

	logger.Info("Puzzle ID obtained", zap.String("id", puzzleResp.PuzzleID))
	return puzzleResp.PuzzleID, nil
}

func getPuzzleImage(puzzleID, userAgent string, proxy string) (string, error) {
	client := resty.New().
		SetTimeout(30 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(5 * time.Second).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetProxy(proxy).
		SetHeaders(map[string]string{
			"accept":          "*/*",
			"accept-language": "en-US,en;q=0.9",
			"user-agent":      userAgent,
		})

	url := fmt.Sprintf("https://www.aeropres.in/chromeapi/dawn/v1/puzzle/get-puzzle-image?puzzle_id=%s&appid=undefined", puzzleID)
	resp, err := client.R().Get(url)

	if err != nil {
		return "", fmt.Errorf("failed to get puzzle image: %v", err)
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	var imageResp request.PuzzleImageResponse
	if err := json.Unmarshal(resp.Body(), &imageResp); err != nil {
		return "", fmt.Errorf("failed to parse image response: %v", err)
	}

	if !imageResp.Success {
		return "", fmt.Errorf("image request unsuccessful")
	}

	logger.Info("Puzzle image obtained")
	return imageResp.ImgBase64, nil
}

// solve puzzle
func solvePuzzle(email string, proxy string, userAgent string) (string, string, error) {
	puzzleID, err := getPuzzleID(userAgent, proxy)
	if err != nil {
		return "", "", fmt.Errorf("failed to get puzzle: %v", err)
	}

	imgBase64, err := getPuzzleImage(puzzleID, userAgent, proxy)
	if err != nil {
		return "", "", fmt.Errorf("failed to get puzzle image: %v", err)
	}

	twoCaptchaKey := os.Getenv("TWOCAPTCHA_KEY")
	taskID, err := createCaptchaTask(twoCaptchaKey, imgBase64)
	if err != nil {
		return "", "", fmt.Errorf("failed to create captcha task: %v", err)
	}

	solution, err := getCaptchaResult(twoCaptchaKey, taskID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get captcha result: %v", err)
	}

	logger.Info("Puzzle solved successfully",
		zap.String("account", email),
		zap.String("solution", solution))

	return puzzleID, solution, nil
}

// captcha logic
func createCaptchaTask(apiKey, imgBase64 string) (int64, error) {
	payload := request.CreateTaskRequest{
		ClientKey: apiKey,
		SoftID:    4706,
		Task: request.Task{
			Type:      "ImageToTextTask",
			Body:      imgBase64,
			Phrase:    false,
			Case:      false,
			Numeric:   0,
			Math:      false,
			MinLength: 0,
			MaxLength: 0,
			Comment:   "Pay close attention to the letter case.",
		},
	}

	client := resty.New().
		SetTimeout(30 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(5 * time.Second)

	resp, err := client.R().
		SetBody(payload).
		Post(constant.TwoCaptchaURL + "/createTask")

	if err != nil {
		return 0, fmt.Errorf("failed to create captcha task: %v", err)
	}

	if resp.StatusCode() != 200 {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	var result request.CreateTaskResponse
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return 0, fmt.Errorf("failed to parse create task response: %v", err)
	}

	if result.ErrorID != 0 {
		return 0, fmt.Errorf("2captcha error: %d", result.ErrorID)
	}

	logger.Info("Captcha task created", zap.Int64("taskId", result.TaskID))
	return result.TaskID, nil
}

func getCaptchaResult(apiKey string, taskID int64) (string, error) {
	payload := request.GetResultRequest{
		ClientKey: apiKey,
		TaskID:    taskID,
	}

	client := resty.New().
		SetTimeout(30 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(5 * time.Second)

	for attempt := 0; attempt < constant.MaxRetries; attempt++ {
		resp, err := client.R().
			SetBody(payload).
			Post(constant.TwoCaptchaURL + "/getTaskResult")

		if err != nil {
			return "", fmt.Errorf("failed to get captcha result: %v", err)
		}

		if resp.StatusCode() != 200 {
			return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode())
		}

		var result request.GetResultResponse
		if err := json.Unmarshal(resp.Body(), &result); err != nil {
			return "", fmt.Errorf("failed to parse result response: %v", err)
		}

		if result.ErrorID != 0 {
			return "", fmt.Errorf("2captcha error: %d", result.ErrorID)
		}

		if result.Status == "ready" {
			logger.Info("Captcha solved", zap.String("text", result.Solution.Text))
			return result.Solution.Text, nil
		}

		if attempt < constant.MaxRetries-1 {
			logger.Info("Captcha still processing, waiting...",
				zap.Int("attempt", attempt+1),
				zap.Int("maxAttempts", constant.MaxRetries))
			time.Sleep(constant.RetryInterval)
		}
	}

	return "", fmt.Errorf("captcha solving timed out after %d attempts", constant.MaxRetries)
}

// login
func isBadGateway(statusCode int, body string) bool {
	return statusCode == 502 || strings.Contains(body, "502 Bad Gateway")
}

func processLogin(account *Account) error {
	maxRetries := 10
	userAgent := browser.Chrome()

	logger.Info("Using dedicated proxy for login process",
		zap.String("email", account.Auth.Email),
		zap.String("proxy", account.LoginProxy))

	for attempt := 0; attempt < maxRetries; attempt++ {
		puzzleID, solution, err := solvePuzzle(account.Auth.Email, account.LoginProxy, userAgent)
		if err != nil {
			logger.Error("Failed to solve puzzle",
				zap.String("email", account.Auth.Email),
				zap.String("proxy", account.LoginProxy),
				zap.Int("attempt", attempt+1),
				zap.Error(err))

			if attempt < maxRetries-1 {
				time.Sleep(3 * time.Second)
				continue
			}
			return fmt.Errorf("failed to solve puzzle after %d attempts: %v", maxRetries, err)
		}

		token, err := loginDawn(
			account.Auth.Email,
			account.Auth.Password,
			puzzleID,
			solution,
			userAgent,
			account.LoginProxy,
		)

		if err != nil {
			if strings.Contains(err.Error(), "Invalid username or Password") {
				return &InvalidCredentialsError{Email: account.Auth.Email}
			}

			if strings.Contains(err.Error(), "502 Bad Gateway") {
				logger.Warn("Received 502 Bad Gateway",
					zap.String("email", account.Auth.Email),
					zap.String("proxy", account.LoginProxy),
					zap.Int("attempt", attempt+1))

				if attempt < maxRetries-1 {
					logger.Info("Waiting before retry...",
						zap.String("email", account.Auth.Email),
						zap.Int("nextAttempt", attempt+2))
					time.Sleep(3 * time.Second)
					continue
				}
			} else if strings.Contains(err.Error(), "Incorrect answer") {
				logger.Warn("Incorrect puzzle answer",
					zap.String("email", account.Auth.Email),
					zap.Int("attempt", attempt+1),
					zap.String("solution", solution))

				if attempt < maxRetries-1 {
					time.Sleep(2 * time.Second)
					continue
				}
			}

			return fmt.Errorf("login failed after %d attempts: %v", attempt+1, err)
		}

		account.Token = token
		logger.Info("Login completed",
			zap.String("email", account.Auth.Email),
			zap.String("proxy", account.LoginProxy),
			zap.Int("attemptsTaken", attempt+1))

		return nil
	}

	return fmt.Errorf("exceeded maximum retry attempts (%d)", maxRetries)
}

func loginDawn(email, password, puzzleID, captchaSolution, userAgent, proxy string) (string, error) {
	loginPayload := request.LoginRequest{
		Username: email,
		Password: password,
		LoginData: request.LoginData{
			Version:  "1.0.9",
			DateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		},
		PuzzleID: puzzleID,
		Answer:   captchaSolution,
	}

	client := resty.New().
		SetTimeout(30 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(5 * time.Second).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetProxy(proxy).
		SetHeaders(map[string]string{
			"accept":          "*/*",
			"accept-language": "en-US,en;q=0.9",
			"content-type":    "application/json",
			"user-agent":      userAgent,
		})

	resp, err := client.R().
		SetBody(loginPayload).
		Post("https://www.aeropres.in/chromeapi/dawn/v1/user/login/v2?appid=undefined")

	if err != nil {
		return "", fmt.Errorf("login request failed: %v", err)
	}

	// 502 err case
	if isBadGateway(resp.StatusCode(), resp.String()) {
		return "", fmt.Errorf("502 Bad Gateway received")
	}

	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		var errorResp struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
			MsgCode int    `json:"msgcode"`
		}

		if err := json.Unmarshal(resp.Body(), &errorResp); err != nil {
			return "", fmt.Errorf("login failed with status code: %d, body: %s",
				resp.StatusCode(), resp.String())
		}

		return "", fmt.Errorf("%s", errorResp.Message)
	}

	var loginResp request.LoginResponse
	if err := json.Unmarshal(resp.Body(), &loginResp); err != nil {
		return "", fmt.Errorf("failed to parse login response: %v", err)
	}

	if !loginResp.Status {
		return "", fmt.Errorf("%s", loginResp.Message)
	}

	logger.Info("Login successful",
		zap.String("email", email),
		zap.String("serverName", loginResp.ServerName))

	return loginResp.Data.Token, nil
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

// credential checkkk
type InvalidCredentialsError struct {
	Email string
}

func (e *InvalidCredentialsError) Error() string {
	return fmt.Sprintf("Invalid credentials for %s", e.Email)
}

func isInvalidCredentials(err error) bool {
	return strings.Contains(err.Error(), "Invalid username or Password")
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
	maxRetries := 5

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
			"_v":           "1.0.9",
		}

		res, err := client.R().
			SetHeader("authorization", fmt.Sprintf("Bearer %v", account.Token)).
			SetBody(keepAliveRequest).
			Post(constant.KeepAliveURL)

		if err != nil {
			logger.Error("Keep alive error",
				zap.String("acc", account.Auth.Email),
				zap.Error(err))
		} else {
			response := res.String()
			if isSessionExpired(response) {
				logger.Warn("Session expired, attempting to relogin",
					zap.String("acc", account.Auth.Email))

				//attempt relogin
				for retry := 0; retry < maxRetries; retry++ {
					err := processLogin(&account)
					if err != nil {
						logger.Error("Relogin attempt failed",
							zap.String("acc", account.Auth.Email),
							zap.Int("attempt", retry+1),
							zap.Int("maxAttempts", maxRetries),
							zap.Error(err))

						if retry < maxRetries-1 {
							time.Sleep(3 * time.Second)
							continue
						}
						break
					}

					logger.Info("Relogin successful",
						zap.String("acc", account.Auth.Email),
						zap.Int("attemptsTaken", retry+1))
					break
				}
				continue
			}

			logger.Info("Keep alive success",
				zap.String("acc", account.Auth.Email),
				zap.String("res", cleanResponse(response)))
		}

		// get points
		res, err = client.R().
			SetHeader("authorization", fmt.Sprintf("Bearer %v", account.Token)).
			Get(constant.GetPointURL)

		if err != nil {
			logger.Error("Get point error",
				zap.String("acc", account.Auth.Email),
				zap.Error(err))
		} else {
			response := res.String()
			if isSessionExpired(response) {
				logger.Warn("Session expired during points check, attempting to relogin",
					zap.String("acc", account.Auth.Email))

				// attempt relogin
				for retry := 0; retry < maxRetries; retry++ {
					err := processLogin(&account)
					if err != nil {
						logger.Error("Relogin attempt failed during points check",
							zap.String("acc", account.Auth.Email),
							zap.Int("attempt", retry+1),
							zap.Int("maxAttempts", maxRetries),
							zap.Error(err))

						if retry < maxRetries-1 {
							time.Sleep(3 * time.Second)
							continue
						}
						break
					}

					logger.Info("Relogin successful after points check error",
						zap.String("acc", account.Auth.Email),
						zap.Int("attemptsTaken", retry+1))
					break
				}
				continue
			}

			points, err := calculateTotalPoints(response)
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
	// init logger
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger = zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(config),
		zapcore.AddSync(colorable.NewColorableStdout()),
		zapcore.DebugLevel,
	))

	//load .env file
	if err := godotenv.Load(); err != nil {
		logger.Fatal("Error loading .env file", zap.Error(err))
	}

	botToken := os.Getenv("BOT_TOKEN")
	if botToken == "" {
		logger.Fatal("BOT_TOKEN not found in .env")
	}

	twoCaptchaKey := os.Getenv("TWOCAPTCHA_KEY")
	if twoCaptchaKey == "" {
		logger.Fatal("TWOCAPTCHA_KEY not found in .env")
	}

	// read cred on login.txt
	userIDs, auths, err := parseLoginFile("login.txt")
	if err != nil {
		logger.Fatal("Error parsing login file", zap.Error(err))
	}

	// read proxies
	proxies, err := readProxies("proxy.txt")
	if err != nil {
		logger.Fatal("Error reading proxy file", zap.Error(err))
	}

	// proxy distributor
	distributor := NewProxyDistributor(userIDs, proxies, logger)
	if err := distributor.Validate(); err != nil {
		logger.Fatal("Proxy distribution validation failed", zap.Error(err))
	}

	// get proxy distribution
	proxyDistribution := distributor.DistributeProxies()

	// accounts with distributed proxies
	var accounts []Account
	for i, auth := range auths {
		accounts = append(accounts, Account{
			Auth:       auth,
			Proxies:    proxyDistribution[userIDs[i]], // use all proxies for ping
			LoginProxy: proxies[i],                    // dedicated proxy for login
		})
	}

	logger.Info("Initial setup complete",
		zap.Int("totalAccounts", len(accounts)),
		zap.Int("totalProxies", len(proxies)))

	// start login for each account
	var successfulLogins int
	var skippedAccounts int

	for i := range accounts {
		logger.Info("Processing account...",
			zap.String("email", accounts[i].Auth.Email),
			zap.String("loginProxy", accounts[i].LoginProxy))

		err := processLogin(&accounts[i])
		if err != nil {
			if isInvalidCredentials(err) {
				logger.Error("Skipping account due to invalid credentials",
					zap.String("email", accounts[i].Auth.Email))
				skippedAccounts++
				continue
			}

			logger.Error("Failed to process login",
				zap.String("email", accounts[i].Auth.Email),
				zap.Error(err))
			continue
		}

		successfulLogins++
		logger.Info("Account login successful",
			zap.String("email", accounts[i].Auth.Email),
			zap.Int("successfulLogins", successfulLogins),
			zap.Int("totalAccounts", len(accounts)))
	}

	logger.Info("Login process completed",
		zap.Int("totalAccounts", len(accounts)),
		zap.Int("successfulLogins", successfulLogins),
		zap.Int("skippedAccounts", skippedAccounts))

	if successfulLogins == 0 {
		logger.Fatal("No accounts were successfully logged in")
	}

	// init tele bot
	b, err := bot.New(botToken)
	if err != nil {
		logger.Fatal("Error creating bot", zap.Error(err))
	}

	// telegram handlers
	b.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, handleStart)
	b.RegisterHandler(bot.HandlerTypeMessageText, "/point", bot.MatchTypeExact, func(ctx context.Context, b *bot.Bot, update *models.Update) {
		handlePoint(ctx, b, update, accounts)
	})

	// start ping with goroutines
	logger.Info("Starting ping routines",
		zap.Int("successfulLogins", successfulLogins))

	for _, account := range accounts {
		if account.Token != "" {
			go func(acc Account) {
				userAgent := browser.Chrome()
				logger.Info("Starting ping routine",
					zap.String("email", acc.Auth.Email),
					zap.Int("proxyCount", len(acc.Proxies)))
				ping(acc, userAgent)
			}(account)
		}
	}

	// start telegram bot
	logger.Info("Starting Telegram bot")
	b.Start(context.Background())
}
