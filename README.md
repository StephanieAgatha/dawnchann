# Dawn Bot

A Go-based automation bot for Dawn platform with proxy support and Telegram integration.

## ⚡ Key Features

- Multiple account management
- Proxy rotation support
- Telegram bot integration (optional)
- Automatic relogin on session expiry
- Puzzle solver with 2captcha integration
- Smart proxy distribution
- Real-time point monitoring
- Beautiful logging with Uber's Zap

## 🚀 Prerequisites

```bash
go 1.19 or higher
```

## 🛠️ Configuration

### Files Setup
Create the following files in your project directory:

1. `.env` - Environment variables:
   ```env
   TWOCAPTCHA_KEY=your_2captcha_api_key
   BOT_TOKEN=your_telegram_bot_token    # Optional
   CHAT_ID=your_telegram_chat_id        # Optional
   ```

2. `login.txt` - Account credentials (one per line):
   ```
   email1@example.com|password1
   email2@example.com|password2
   ```

3. `proxy.txt` - Proxy list (one per line):
   ```
   http://user:pass@host:port
   socks5://user:pass@host:port
   http://host:port
   ```

## 🚀 Usage

1. Run application :
   ```bash
   go run main.go
   ```

2. Telegram Commands:
- `/start` - Start the bot
- `/point` - Check points for all accounts

3. Example Output:
   ```
   🔍 Dawn Points Checker Report
   📊 Total Accounts: 2

1. us****1@example.com
   ✅ Points: 1,234.56

2. us****2@example.com
   ✅ Points: 5,678.90

📈 Summary:
• Success Rate: 2/2 (100.0%)
• Average Points: 3,456.73
• Total Points: 6,913.46

🕒 2024-11-28 10:30:00 WIB
