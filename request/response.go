package request

type LoginResponse struct {
	Status     bool        `json:"status"`
	Message    string      `json:"message"`
	Data       LoginResult `json:"data"`
	ServerName string      `json:"servername"`
}

type PointResponse struct {
	Status     bool   `json:"status"`
	Message    string `json:"message"`
	ServerName string `json:"servername"`
	Data       struct {
		ReferralPoint struct {
			ID         string  `json:"_id"`
			Email      string  `json:"email"`
			RefCode    string  `json:"referralCode"`
			ReferredBy string  `json:"referredBy"`
			Commission float64 `json:"commission"`
			CreatedAt  string  `json:"createdAt"`
			UpdatedAt  string  `json:"updatedAt"`
			V          int     `json:"__v"`
		} `json:"referralPoint"`
		RewardPoint struct {
			ID               string  `json:"_id"`
			UserID           string  `json:"userId"`
			LastActive       string  `json:"lastActive"`
			ActiveStreak     int     `json:"activeStreak"`
			Points           float64 `json:"points"`
			RegisterPoints   float64 `json:"registerpoints"`
			SignInPoints     float64 `json:"signinpoints"`
			RegisterDate     string  `json:"registerpointsdate"`
			SignInDate       string  `json:"signinpointsdate"`
			TwitterXIDPoints float64 `json:"twitter_x_id_points"`
			DiscordIDPoints  float64 `json:"discordid_points"`
			TelegramIDPoints float64 `json:"telegramid_points"`
			CreatedAt        string  `json:"createdAt"`
			UpdatedAt        string  `json:"updatedAt"`
			V                int     `json:"__v"`
			ActiveStatus     string  `json:"active_status"`
			LastKeepAlive    string  `json:"lastKeepAlive"`
			IsNewPointSync   bool    `json:"isNewPointSync"`
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

type KeepAliveResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
