package constant

import (
	"time"
)

const (
	MaxRetries    = 50
	RetryInterval = 5 * time.Second
	TwoCaptchaURL = "https://api.2captcha.com"
)
