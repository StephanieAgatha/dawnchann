package request

type LoginResponse struct {
	Status     bool        `json:"status"`
	Message    string      `json:"message"`
	Data       LoginResult `json:"data"`
	ServerName string      `json:"servername"`
}

type PointResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Data    struct {
		ReferralPoint struct {
			Commission float64 `json:"commission"`
		} `json:"referralPoint"`
		RewardPoint struct {
			Points           float64 `json:"points"`
			RegisterPoints   float64 `json:"registerpoints"`
			SignInPoints     float64 `json:"signinpoints"`
			TwitterXIDPoints float64 `json:"twitter_x_id_points"`
			DiscordIDPoints  float64 `json:"discordid_points"`
			TelegramIDPoints float64 `json:"telegramid_points"`
			BonusPoints      float64 `json:"bonus_points"`
		} `json:"rewardPoint"`
	} `json:"data"`
}

type PuzzleResponse struct {
	Success  bool   `json:"success"`
	PuzzleID string `json:"puzzle_id"`
}

type PuzzleImageResponse struct {
	Success   bool   `json:"success"`
	ImgBase64 string `json:"imgBase64"`
	Data      any    `json:"data"`
}

type CreateTaskResponse struct {
	ErrorID int   `json:"errorId"`
	TaskID  int64 `json:"taskId"`
}

type GetResultResponse struct {
	ErrorID  int      `json:"errorId"`
	Status   string   `json:"status"`
	Solution Solution `json:"solution"`
}
