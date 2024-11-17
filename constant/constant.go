package constant

import (
	"fmt"
	"time"
)

const (
	BaseUrl       = "https://www.aeropres.in/chromeapi/dawn/v1"
	MaxRetries    = 10
	RetryInterval = 5 * time.Second
	TwoCaptchaURL = "https://api.2captcha.com"
)

var (
	KeepAliveURL = fmt.Sprintf("%v/userreward/keepalive", BaseUrl)
	GetPointURL  = "https://www.aeropres.in/api/atom/v1/userreferral/getpoint"
	LoginURL     = "https://www.aeropres.in/chromeapi/dawn/v1/user/login"
)
