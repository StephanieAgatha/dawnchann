package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"dawnchann/constant"
	"dawnchann/request"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/briandowns/spinner"
	browser "github.com/itzngga/fake-useragent"
	"github.com/joho/godotenv"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/mattn/go-colorable"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger          *zap.Logger
	spinnerInstance *spinner.Spinner
	outputLock      = make(chan struct{}, 1)

	extensionID = "fpdkjdnhkakefebpekbdhillbhonfjjp"
	chromeUA    = browser.Chrome()
)

// init
func init() {
	outputLock <- struct{}{}
}

type Account struct {
	Auth       request.Authentication
	Proxies    []string
	Token      string
	LoginProxy string
	AppID      string
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

type syncWriter struct {
	output zapcore.WriteSyncer
}

func (w *syncWriter) Write(p []byte) (n int, err error) {
	<-outputLock
	defer func() { outputLock <- struct{}{} }()

	fmt.Print("\r\033[K") // clear line before writing log
	return w.output.Write(p)
}

func (w *syncWriter) Sync() error {
	return w.output.Sync()
}

func spin(duration time.Duration) {
	<-outputLock // acquire lock

	if spinnerInstance == nil {
		spinnerInstance = spinner.New(spinner.CharSets[36], 100*time.Millisecond)
		spinnerInstance.Color("yellow")
		spinnerInstance.Suffix = " Waiting..."
	}

	fmt.Print("\r\033[K") // clear line before starting
	spinnerInstance.Start()
	time.Sleep(duration)
	spinnerInstance.Stop()
	fmt.Print("\r\033[K") // clear line after stopping

	outputLock <- struct{}{} // release lock
}

func initLogger() *zap.Logger {
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder
	originalOutput := zapcore.AddSync(colorable.NewColorableStdout())
	locker := zapcore.Lock(zapcore.AddSync(&syncWriter{output: originalOutput}))

	config.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		jakarta, err := time.LoadLocation("Asia/Jakarta")
		if err != nil {
			jakarta = time.UTC
		}
		enc.AppendString(t.In(jakarta).Format("02/01/2006 15:04:05"))
	}

	return zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(config),
		locker,
		zapcore.DebugLevel,
	))
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

// do req using fasthttp
func doRequest(client *fasthttp.Client, method, url string, body []byte, headers map[string]string, timeout time.Duration) ([]byte, int, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod(method)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if body != nil {
		req.SetBody(body)
	}

	if err := client.DoTimeout(req, resp, timeout); err != nil {
		return nil, 0, err
	}

	bodyBytes := resp.Body()
	if len(bodyBytes) > 0 && bodyBytes[0] == 0x1f && bodyBytes[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, resp.StatusCode(), fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer reader.Close()

		bodyBytes, err = io.ReadAll(reader)
		if err != nil {
			return nil, resp.StatusCode(), fmt.Errorf("failed to read gzipped content: %v", err)
		}
	}

	return bodyBytes, resp.StatusCode(), nil
}

// fasthttp client
func createClient(proxy string) *fasthttp.Client {
	return &fasthttp.Client{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		Dial: fasthttpproxy.FasthttpHTTPDialer(proxy),
	}
}

// gen app id
func generateappID() string {
	const charset = "abcdef0123456789"
	const length = 24
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

// base header
func getBaseHeaders(userAgent string) map[string]string {
	return map[string]string{
		"accept":          "*/*",
		"accept-language": "en-US,en;q=0.9",
		"accept-encoding": "gzip",
		"content-type":    "application/json",
		"user-agent":      userAgent,
	}
}

// get puzzle
func getPuzzleID(proxy string) (string, string, error) {
	appID := generateappID()
	logger.Info("app id generated", zap.String("appid", appID))

	client := createClient(proxy)
	headers := getBaseHeaders(chromeUA)
	headers["origin"] = fmt.Sprintf("chrome-extension://%s", extensionID)

	body, statusCode, err := doRequest(
		client,
		fasthttp.MethodGet,
		"https://www.aeropres.in/chromeapi/dawn/v1/puzzle/get-puzzle?appid="+appID,
		nil,
		headers,
		30*time.Second,
	)

	if err != nil {
		return "", "", fmt.Errorf("failed to get puzzle: %v", err)
	}

	if statusCode != 200 && statusCode != 201 {
		return "", "", fmt.Errorf("unexpected status code: %d", statusCode)
	}

	var puzzleResp request.PuzzleResponse
	if err := json.Unmarshal(body, &puzzleResp); err != nil {
		return "", "", fmt.Errorf("failed to parse puzzle response: %v", err)
	}

	if !puzzleResp.Success {
		return "", "", fmt.Errorf("puzzle request unsuccessful")
	}

	logger.Info("puzzle id obtained", zap.String("puzzleid", puzzleResp.PuzzleID))
	return puzzleResp.PuzzleID, appID, nil
}

func getPuzzleImage(puzzleID, appID, userAgent string, proxy string) (string, error) {
	client := createClient(proxy)
	headers := getBaseHeaders(userAgent)

	body, statusCode, err := doRequest(
		client,
		fasthttp.MethodGet,
		fmt.Sprintf("https://www.aeropres.in/chromeapi/dawn/v1/puzzle/get-puzzle-image?puzzle_id=%s&appid=%s", puzzleID, appID),
		nil,
		headers,
		30*time.Second,
	)

	if err != nil {
		return "", fmt.Errorf("failed to get puzzle image: %v", err)
	}

	if statusCode != 200 && statusCode != 201 {
		return "", fmt.Errorf("unexpected status code: %d", statusCode)
	}

	var imageResp request.PuzzleImageResponse
	if err := json.Unmarshal(body, &imageResp); err != nil {
		return "", fmt.Errorf("failed to parse image response: %v", err)
	}

	if !imageResp.Success {
		return "", fmt.Errorf("image request unsuccessful")
	}

	logger.Info("Puzzle image obtained")
	return imageResp.ImgBase64, nil
}

// solve puzzle
func solvePuzzle(email string, proxy string) (string, string, string, error) {
	userAgent := browser.Chrome()

	// get puzzle id
	puzzleID, appID, err := getPuzzleID(proxy)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get puzzle: %v", err)
	}

	// get puzzle image
	imgBase64, err := getPuzzleImage(puzzleID, appID, userAgent, proxy)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get puzzle image: %v", err)
	}

	//captcha task
	twoCaptchaKey := os.Getenv("TWOCAPTCHA_KEY")
	taskID, err := createCaptchaTask(twoCaptchaKey, imgBase64)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create captcha task: %v", err)
	}

	solution, err := getCaptchaResult(twoCaptchaKey, taskID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get captcha result: %v", err)
	}

	logger.Info("Puzzle solved successfully",
		zap.String("account", email),
		zap.String("solution", solution))

	return puzzleID, solution, appID, nil
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

	client := &fasthttp.Client{
		MaxIdleConnDuration: 30 * time.Second,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal payload: %v", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	body, statusCode, err := doRequest(
		client,
		fasthttp.MethodPost,
		constant.TwoCaptchaURL+"/createTask",
		payloadBytes,
		headers,
		30*time.Second,
	)

	if err != nil {
		return 0, fmt.Errorf("failed to create captcha task: %v", err)
	}

	if statusCode != 200 {
		return 0, fmt.Errorf("unexpected status code: %d", statusCode)
	}

	var result request.CreateTaskResponse
	if err := json.Unmarshal(body, &result); err != nil {
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

	client := &fasthttp.Client{
		MaxIdleConnDuration: 30 * time.Second,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %v", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	for attempt := 0; attempt < constant.MaxRetries; attempt++ {
		body, statusCode, err := doRequest(
			client,
			fasthttp.MethodPost,
			constant.TwoCaptchaURL+"/getTaskResult",
			payloadBytes,
			headers,
			30*time.Second,
		)

		if err != nil {
			return "", fmt.Errorf("failed to get captcha result: %v", err)
		}

		if statusCode != 200 {
			return "", fmt.Errorf("unexpected status code: %d", statusCode)
		}

		var result request.GetResultResponse
		if err := json.Unmarshal(body, &result); err != nil {
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
			spin(constant.RetryInterval)
		}
	}

	return "", fmt.Errorf("captcha solving timed out after %d attempts", constant.MaxRetries)
}

// login
func processLogin(account *Account) error {
	maxRetries := 50

	for attempt := 0; attempt < maxRetries; attempt++ {
		puzzleID, solution, appID, err := solvePuzzle(account.Auth.Email, account.LoginProxy)
		if err != nil {
			logger.Error("Failed to solve puzzle",
				zap.String("email", account.Auth.Email),
				zap.String("proxy", account.LoginProxy),
				zap.Int("attempt", attempt+1),
				zap.Error(err))

			if attempt < maxRetries-1 {
				spin(3 * time.Second)
				continue
			}
			return fmt.Errorf("failed to solve puzzle after %d attempts: %v", maxRetries, err)
		}
		account.AppID = appID

		token, err := loginDawn(
			account.Auth.Email,
			account.Auth.Password,
			puzzleID,
			solution,
			appID,
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
					spin(3 * time.Second)
					continue
				}
			} else if strings.Contains(err.Error(), "Incorrect answer") {
				logger.Warn("Incorrect puzzle answer",
					zap.String("email", account.Auth.Email),
					zap.Int("attempt", attempt+1),
					zap.String("solution", solution))

				if attempt < maxRetries-1 {
					spin(2 * time.Second)
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

func loginDawn(email, password, puzzleID, captchaSolution, appID, proxy string) (string, error) {
	loginPayload := request.LoginRequest{
		Username: email,
		Password: password,
		LoginData: request.LoginData{
			Version:  "1.1.2",
			DateTime: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		},
		PuzzleID: puzzleID,
		Answer:   captchaSolution,
	}

	userAgent := browser.Chrome()
	client := createClient(proxy)
	headers := getBaseHeaders(userAgent)
	headers["origin"] = "chrome-extension://fpdkjdnhkakefebpekbdhillbhonfjjp"

	payload, err := json.Marshal(loginPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal login payload: %v", err)
	}

	body, statusCode, err := doRequest(
		client,
		fasthttp.MethodPost,
		"https://www.aeropres.in/chromeapi/dawn/v1/user/login/v2?appid="+appID,
		payload,
		headers,
		2*time.Minute,
	)

	if err != nil {
		return "", fmt.Errorf("login request failed: %v", err)
	}

	if statusCode != 200 && statusCode != 201 {
		return "", fmt.Errorf("unexpected status code: %d", statusCode)
	}

	var loginResp request.LoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return "", fmt.Errorf("failed to parse login response: %v, raw: %s", err, string(body))
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
		return 0, fmt.Errorf("error fetching points ")
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

// get points
func getPoints(client *fasthttp.Client, account Account, appID string) (float64, error) {
	headers := getBaseHeaders(browser.Chrome())
	headers["authorization"] = fmt.Sprintf("Bearer %v", account.Token)

	body, statusCode, err := doRequest(
		client,
		fasthttp.MethodGet,
		"https://www.aeropres.in/api/atom/v1/userreferral/getpoint?appid="+appID,
		nil,
		headers,
		30*time.Second,
	)

	if err != nil {
		return 0, err
	}

	if statusCode != 200 && statusCode != 201 {
		return 0, fmt.Errorf("unexpected status code: %d", statusCode)
	}

	response := string(body)
	if isSessionExpired(response) {
		return 0, &SessionExpiredError{Message: "Session expired during points check"}
	}

	points, err := calculateTotalPoints(response)
	if err != nil {
		return 0, fmt.Errorf("failed to calculate points: %v", err)
	}

	return points, nil
}

// ping
func ping(account Account, userAgent string) {
	currentProxyIndex := 0

	for {
		proxy := account.Proxies[currentProxyIndex]
		currentProxyIndex = (currentProxyIndex + 1) % len(account.Proxies)

		client := &fasthttp.Client{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			Dial: fasthttpproxy.FasthttpHTTPDialer(proxy),
		}

		headers := getBaseHeaders(userAgent)
		headers["authorization"] = fmt.Sprintf("Bearer %v", account.Token)
		headers["origin"] = fmt.Sprintf("chrome-extension://%s", extensionID)

		keepAliveRequest := map[string]interface{}{
			"username":     account.Auth.Email,
			"extensionid":  extensionID,
			"numberoftabs": 0,
			"_v":           "1.1.2",
		}

		payload, err := json.Marshal(keepAliveRequest)
		if err != nil {
			logger.Error("Failed to marshal keepalive request", zap.Error(err))
			continue
		}

		body, statusCode, err := doRequest(
			client,
			fasthttp.MethodPost,
			fmt.Sprintf("https://www.aeropres.in/chromeapi/dawn/v1/userreward/keepalive?appid=%s", account.AppID),
			payload,
			headers,
			30*time.Second,
		)

		if err != nil {
			logger.Error("Keep alive error",
				zap.String("acc", account.Auth.Email),
				zap.Error(err))
			continue
		}

		var keepAliveResp request.KeepAliveResponse
		if err := json.Unmarshal(body, &keepAliveResp); err == nil {
			if statusCode != 200 && statusCode != 201 {
				logger.Error("Keep alive failed",
					zap.String("acc", account.Auth.Email),
					zap.Int("status", statusCode),
					zap.String("message", keepAliveResp.Message))
			} else {
				logger.Info("Keep alive success",
					zap.String("acc", account.Auth.Email),
					//zap.Int("status", statusCode),
					zap.String("message", keepAliveResp.Message))
			}
		}

		if isSessionExpired(string(body)) {
			logger.Warn("Session expired, attempting relogin",
				zap.String("acc", account.Auth.Email))

			if err := processLogin(&account); err != nil {
				logger.Error("Relogin attempt failed",
					zap.String("acc", account.Auth.Email),
					zap.Error(err))
				continue
			}

			logger.Info("Relogin successful",
				zap.String("acc", account.Auth.Email))
			continue
		}

		points, err := getPoints(client, account, account.AppID)
		if err != nil {
			var sessionExpiredError *SessionExpiredError
			if errors.As(err, &sessionExpiredError) {
				logger.Warn("Session expired during points check",
					zap.String("acc", account.Auth.Email))

				if err := processLogin(&account); err != nil {
					logger.Error("Relogin attempt failed",
						zap.String("acc", account.Auth.Email),
						zap.Error(err))
				}
				continue
			}

			logger.Error("Error calculating points",
				zap.String("acc", account.Auth.Email),
				zap.Error(err))
		} else {
			logger.Info("Points calculated",
				zap.String("acc", account.Auth.Email),
				zap.String("points", formatReadablePoints(points)))
		}

		spin(30 * time.Second)
	}
}

// telegram logic
func initTeleBot(botToken string, accounts []Account) {
	maxRetries := 5
	retryDelay := 5 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		logger.Info("Initializing Telegram bot...",
			zap.Int("attempt", attempt),
			zap.Int("maxAttempts", maxRetries))

		b, err := bot.New(botToken)
		if err != nil {
			if attempt == maxRetries {
				logger.Error("Failed to initialize Telegram bot after all retries",
					zap.Int("attempts", attempt),
					zap.Error(err))
				return
			}

			logger.Warn("Failed to initialize Telegram bot, retrying...",
				zap.Int("attempt", attempt),
				zap.Int("maxAttempts", maxRetries),
				zap.Duration("retryDelay", retryDelay),
				zap.Error(err))

			time.Sleep(retryDelay)
			retryDelay *= 2
			continue
		}

		// Successfully initialized bot
		b.RegisterHandler(bot.HandlerTypeMessageText, "/start", bot.MatchTypeExact, handleStart)
		b.RegisterHandler(bot.HandlerTypeMessageText, "/point", bot.MatchTypeExact, func(ctx context.Context, b *bot.Bot, update *models.Update) {
			handlePoint(ctx, b, update, accounts)
		})

		logger.Info("Successfully initialized Telegram bot",
			zap.Int("attemptsTaken", attempt))

		logger.Info("Starting Telegram bot")
		b.Start(context.Background())
		return
	}
}

// authorized chat
func isAuthorizedChat(chatID int64) bool {
	allowedChatID := os.Getenv("CHAT_ID")
	if allowedChatID == "" {
		return false
	}
	authorizedID, err := strconv.ParseInt(allowedChatID, 10, 64)
	if err != nil {
		logger.Error("Failed to parse CHAT_ID", zap.Error(err))
		return false
	}

	return chatID == authorizedID
}

func logUserInteraction(update *models.Update, action string) {
	username := update.Message.From.Username
	if username == "" {
		username = fmt.Sprintf("%s %s", update.Message.From.FirstName, update.Message.From.LastName)
	}
	log.Printf("User %s %s", username, action)
}

func handleStart(ctx context.Context, b *bot.Bot, update *models.Update) {
	logUserInteraction(update, "attempted to start the bot")

	if !isAuthorizedChat(update.Message.Chat.ID) {
		logger.Warn("Unauthorized access attempt",
			zap.Int64("chatID", update.Message.Chat.ID),
			zap.String("username", update.Message.From.Username))

		if _, err := b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "⛔ Unauthorized. You don't have permission to use this bot.",
		}); err != nil {
			log.Printf("Error sending unauthorized message: %v", err)
		}
		return
	}

	if _, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "Welcome, please send the /point command to check your points",
	}); err != nil {
		log.Printf("Error sending message: %v", err)
	}
}

func handlePoint(ctx context.Context, b *bot.Bot, update *models.Update, accounts []Account) {
	if !isAuthorizedChat(update.Message.Chat.ID) {
		logger.Warn("Unauthorized points request attempt",
			zap.Int64("chatID", update.Message.Chat.ID),
			zap.String("username", update.Message.From.Username))

		if _, err := b.SendMessage(ctx, &bot.SendMessageParams{
			ChatID: update.Message.Chat.ID,
			Text:   "⛔ Unauthorized. You don't have permission to use this bot.",
		}); err != nil {
			log.Printf("Error sending unauthorized message: %v", err)
		}
		return
	}
	logUserInteraction(update, "requested point information")

	// bot send reply first
	if _, err := b.SendMessage(ctx, &bot.SendMessageParams{
		ChatID: update.Message.Chat.ID,
		Text:   "We got your request, please wait ...",
	}); err != nil {
		log.Printf("Error sending got request message : %v", err)
	}

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
		linePrefix := fmt.Sprintf("%d. %s", i+1, maskEmail(account.Auth.Email))

		var points float64
		var pointsErr error
		maxAttempts := 3

		for attempt := 0; attempt < maxAttempts; attempt++ {
			proxy := account.Proxies[attempt%len(account.Proxies)]
			userAgent := browser.Chrome()

			client := &fasthttp.Client{
				TLSConfig: &tls.Config{InsecureSkipVerify: true},
				Dial:      fasthttpproxy.FasthttpHTTPDialer(proxy),
			}

			headers := getBaseHeaders(userAgent)
			headers["authorization"] = fmt.Sprintf("Bearer %v", account.Token)

			body, _, err := doRequest(
				client,
				fasthttp.MethodGet,
				"https://www.aeropres.in/api/atom/v1/userreferral/getpoint?appid="+generateappID(),
				nil,
				headers,
				30*time.Second,
			)

			if err != nil {
				logger.Error("Failed to fetch points",
					zap.String("account", maskEmail(account.Auth.Email)),
					zap.Int("attempt", attempt+1),
					zap.Error(err))

				if attempt < maxAttempts-1 {
					spin(2 * time.Second)
					continue
				}

				messageLines = append(messageLines, fmt.Sprintf("%s\n❌ Error: Connection failed\n",
					linePrefix))
				break
			}

			response := string(body)

			if isSessionExpired(response) || strings.Contains(response, "Provider routines") {
				logger.Warn("Session issue detected, attempting relogin",
					zap.String("account", maskEmail(account.Auth.Email)),
					zap.Int("attempt", attempt+1))

				if err := processLogin(&account); err != nil {
					logger.Error("Relogin failed",
						zap.String("account", maskEmail(account.Auth.Email)),
						zap.Error(err))
					if attempt < maxAttempts-1 {
						spin(2 * time.Second)
						continue
					}
					messageLines = append(messageLines, fmt.Sprintf("%s\n❌ Error: Relogin failed\n",
						linePrefix))
					break
				}

				headers["authorization"] = fmt.Sprintf("Bearer %v", account.Token)
				body, _, err = doRequest(
					client,
					fasthttp.MethodGet,
					"https://www.aeropres.in/api/atom/v1/userreferral/getpoint?appid="+generateappID(),
					nil,
					headers,
					30*time.Second,
				)

				if err != nil {
					continue
				}
				response = string(body)
			}

			points, pointsErr = calculateTotalPoints(response)
			if pointsErr == nil {
				break
			}

			if attempt < maxAttempts-1 {
				spin(2 * time.Second)
				continue
			}
		}

		if pointsErr != nil {
			logger.Error("Failed to calculate points after all attempts",
				zap.String("account", maskEmail(account.Auth.Email)),
				zap.Error(pointsErr))
			messageLines = append(messageLines, fmt.Sprintf("%s\n❌ Error: Points calculation failed\n",
				linePrefix))
			continue
		}

		successCount++
		totalPoints += points
		messageLines = append(messageLines, fmt.Sprintf("%s\n✅ Points: %s\n",
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
			spin(time.Second * time.Duration(attempt))
		}
	}
}

func main() {
	// init logger
	logger = initLogger()

	//load .env file
	if err := godotenv.Load(); err != nil {
		logger.Fatal("Error loading .env file", zap.Error(err))
	}

	// check telegram config
	botToken := os.Getenv("BOT_TOKEN")
	chatID := os.Getenv("CHAT_ID")
	telegramEnabled := botToken != "" && chatID != ""

	if !telegramEnabled {
		logger.Info("Telegram bot disabled: bot token or chat not set in .env file")
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

	// start login for each account
	var successfulLogins int
	var skippedAccounts int

	for i := range accounts {
		logger.Info("Processing account...",
			zap.String("email", accounts[i].Auth.Email),
			zap.String("loginProxy", accounts[i].LoginProxy))

		for {
			err := processLogin(&accounts[i])
			if err != nil {
				if isInvalidCredentials(err) {
					logger.Error("Skipping account due to invalid credentials",
						zap.String("email", accounts[i].Auth.Email))
					skippedAccounts++
					break
				}
				logger.Error("Failed to process login, retrying...",
					zap.String("email", accounts[i].Auth.Email),
					zap.Error(err))
				spin(3 * time.Second)
				continue
			}

			successfulLogins++
			logger.Info("Account login successful",
				zap.String("email", accounts[i].Auth.Email),
				zap.Int("successfulLogins", successfulLogins),
				zap.Int("totalAccounts", len(accounts)))
			break
		}
	}

	logger.Info("Login process completed",
		zap.Int("totalAccounts", len(accounts)),
		zap.Int("successfulLogins", successfulLogins),
		zap.Int("skippedAccounts", skippedAccounts))

	if successfulLogins == 0 {
		logger.Fatal("No accounts were successfully logged in")
	}

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

	// init telegram bot only if enabled
	if telegramEnabled {
		initTeleBot(botToken, accounts)
	}

	// if telegram is disabled or failed to start, keep the program running
	select {}
}
