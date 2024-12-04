package constant

import (
	"time"
)

const (
	MaxRetries    = 10
	RetryInterval = 5 * time.Second
	TwoCaptchaURL = "https://api.2captcha.com"
)
