package request

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateTaskRequest struct {
	ClientKey string `json:"clientKey"`
	SoftID    int    `json:"softId"`
	Task      Task   `json:"task"`
}

type Task struct {
	Type      string `json:"type"`
	Body      string `json:"body"`
	Phrase    bool   `json:"phrase"`
	Case      bool   `json:"case"`
	Numeric   int    `json:"numeric"`
	Math      bool   `json:"math"`
	MinLength int    `json:"minLength"`
	MaxLength int    `json:"maxLength"`
	Comment   string `json:"comment"`
}

type GetResultRequest struct {
	ClientKey string `json:"clientKey"`
	TaskID    int64  `json:"taskId"`
}

type Solution struct {
	Text string `json:"text"`
}

type LoginRequest struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	LoginData LoginData `json:"logindata"`
	PuzzleID  string    `json:"puzzle_id"`
	Answer    string    `json:"ans"`
}

type LoginData struct {
	Version  string `json:"_v"`
	DateTime string `json:"datetime"`
}

type LoginResult struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	ID        string `json:"_id"`
	Mobile    string `json:"mobile"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}
