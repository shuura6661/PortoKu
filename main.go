package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/go-echarts/go-echarts/charts"
	_ "github.com/go-sql-driver/mysql"
	"github.com/piquette/finance-go/chart"
	"github.com/piquette/finance-go/datetime"
	"github.com/piquette/finance-go/equity"
	"github.com/piquette/finance-go/quote"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var err error

func init() {
	db, err = sql.Open("mysql", "root@tcp(localhost:3306)/stock_trader")
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
}

// Helper functions for user authentication
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := hashPassword(password)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(w, "Error registering user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var storedHash string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHash)
		if err != nil {
			log.Println("Invalid username or password")
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		if !checkPasswordHash(password, storedHash) {
			log.Println("Invalid username or password")
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Set cookie with the username
		cookie := &http.Cookie{
			Name:  "username",
			Value: username,
			Path:  "/",
			// Secure: true, // Uncomment if using HTTPS
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		log.Println("Set cookie for username:", username)

		// Redirect to the dashboard
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// calculateFibonacciLevels calculates the Fibonacci retracement levels
func calculateFibonacciLevels(high, low float64) map[string]float64 {
	diff := high - low
	levels := map[string]float64{
		"23.6%": high - 0.236*diff,
		"38.2%": high - 0.382*diff,
		"50.0%": high - 0.5*diff,
		"61.8%": high - 0.618*diff,
		"78.6%": high - 0.786*diff,
	}
	return levels
}

// determineZone determines if the current price is in the Buy or Sell zone
func determineZone(currentPrice float64, fibLevels map[string]float64) string {
	if currentPrice < fibLevels["50.0%"] {
		return "Buy"
	}
	return "Sell"
}

type FibLevel struct {
	Level string
	Value float64
}

type TradeIdea struct {
	Index           int
	TakeProfit      float64
	Pips            float64
	RiskRewardRatio float64
}

type ResultData struct {
	Symbol           string
	CurrentPrice     float64
	FiftyTwoWeekHigh float64
	FiftyTwoWeekLow  float64
	MarketCap        float64
	BookValue        float64
	FibonacciLevels  []FibLevel
	TradeIdeas       []TradeIdea
	ChartHTML        template.HTML
}

// Chart rendering functions
func fetchChartData(sym string) ([]string, []float64) {
	now := time.Now()
	yearAgo := now.AddDate(-1, 0, 0)

	p := &chart.Params{
		Symbol:   sym,
		Start:    datetime.New(&yearAgo),
		End:      datetime.New(&now),
		Interval: datetime.OneDay,
	}

	iter := chart.Get(p)
	count := iter.Count()

	x := make([]string, count)
	y := make([]float64, count)

	var date string
	var price float64

	i := 0
	for iter.Next() {
		d := iter.Bar()
		price, _ = d.Close.Round(2).Float64()
		date = time.Unix(int64(d.Timestamp), 0).Format("2006-01-02")

		x[i] = date
		y[i] = price
		i++
	}

	return x, y
}

func renderChart(symbol string) template.HTML {
	line := charts.NewLine()
	line.SetGlobalOptions(charts.TitleOpts{Title: ""})

	x, y := fetchChartData(symbol)

	line.AddXAxis(x)
	line.AddYAxis(symbol, y)

	chartHTML := charts.NewPage()
	chartHTML.Add(line)

	var buffer bytes.Buffer
	chartHTML.Render(&buffer)

	return template.HTML(buffer.String())
}

func displaySymbolViewer(smbl string) (ResultData, error) {
	q, err := quote.Get(smbl)
	if err != nil {
		logrus.Fatalf("Error fetching quote: %v", err)
		return ResultData{}, err
	}
	e, err := equity.Get(smbl)
	if err != nil {
		logrus.Fatalf("Error fetching equity data: %v", err)
		return ResultData{}, err
	}

	currentPrice := q.Ask
	if currentPrice == 0 {
		currentPrice = q.RegularMarketPrice
	}

	return ResultData{
		Symbol:           q.ShortName,
		CurrentPrice:     currentPrice,
		FiftyTwoWeekHigh: q.FiftyTwoWeekHigh,
		FiftyTwoWeekLow:  q.FiftyTwoWeekLow,
		MarketCap:        float64(e.MarketCap),
		BookValue:        float64(e.BookValue),
		FibonacciLevels:  nil,
		TradeIdeas:       nil,
		ChartHTML:        renderChart(smbl),
	}, nil
}

func displayFibonacciLevels(smbl string) (ResultData, error) {
	q, err := quote.Get(smbl)
	if err != nil {
		logrus.Fatalf("Error fetching quote: %v", err)
		return ResultData{}, err
	}

	high := q.FiftyTwoWeekHigh
	low := q.FiftyTwoWeekLow
	currentPrice := q.Ask
	if currentPrice == 0 {
		currentPrice = q.RegularMarketPrice
	}

	fibLevels := calculateFibonacciLevels(high, low)

	var fibSlice []FibLevel
	for level, value := range fibLevels {
		fibSlice = append(fibSlice, FibLevel{Level: level, Value: value})
	}
	sort.Slice(fibSlice, func(i, j int) bool {
		return fibSlice[i].Value < fibSlice[j].Value
	})

	zone := determineZone(currentPrice, fibLevels)

	stopLoss := 0.0
	if zone == "Buy" {
		stopLoss = low
	} else {
		stopLoss = high
	}

	var tradeIdeas []TradeIdea
	risk := math.Abs(currentPrice - stopLoss)
	for i, fib := range fibSlice {
		if (zone == "Buy" && fib.Value > currentPrice) || (zone == "Sell" && fib.Value < currentPrice) {
			reward := math.Abs(currentPrice - fib.Value)
			riskRewardRatio := reward / risk
			tradeIdeas = append(tradeIdeas, TradeIdea{
				Index:           i + 1,
				TakeProfit:      fib.Value,
				Pips:            reward,
				RiskRewardRatio: riskRewardRatio,
			})
		}
	}

	if zone == "Buy" {
		reward := high - currentPrice
		riskRewardRatio := reward / risk
		tradeIdeas = append(tradeIdeas, TradeIdea{
			Index:           len(tradeIdeas) + 1,
			TakeProfit:      high,
			Pips:            reward,
			RiskRewardRatio: riskRewardRatio,
		})
	} else {
		reward := currentPrice - low
		riskRewardRatio := reward / risk
		tradeIdeas = append(tradeIdeas, TradeIdea{
			Index:           len(tradeIdeas) + 1,
			TakeProfit:      low,
			Pips:            reward,
			RiskRewardRatio: riskRewardRatio,
		})
	}

	return ResultData{
		Symbol:           q.ShortName,
		CurrentPrice:     currentPrice,
		FiftyTwoWeekHigh: high,
		FiftyTwoWeekLow:  low,
		FibonacciLevels:  fibSlice,
		TradeIdeas:       tradeIdeas,
		ChartHTML:        renderChart(smbl),
	}, nil
}

func quoteHandler(w http.ResponseWriter, r *http.Request) {
	symbol := r.URL.Query().Get("symbol")
	if symbol == "" {
		http.Error(w, "Symbol is required", http.StatusBadRequest)
		return
	}

	choice := r.URL.Query().Get("choice")
	if choice == "" {
		http.Error(w, "Choice is required", http.StatusBadRequest)
		return
	}

	var resultData ResultData
	var err error
	var tmpl string

	switch choice {
	case "1":
		resultData, err = displaySymbolViewer(symbol)
		tmpl = "templates/symbol_viewer.html"
	case "2":
		resultData, err = displayFibonacciLevels(symbol)
		tmpl = "templates/fibonacci_levels.html"
	default:
		http.Error(w, "Invalid choice", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Error processing request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	t, err := template.ParseFiles(tmpl)
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, resultData)
	if err != nil {
		http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		log.Println("Username cookie not found, redirecting to login")
		// If cookie is not found, redirect to login
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := cookie.Value
	log.Println("Username from cookie:", username)

	tmpl, err := template.ParseFiles("templates/dashboard.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, struct{ Username string }{Username: username})
	if err != nil {
		http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func addSymbolHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	if r.Method == "POST" {
		symbol := r.FormValue("symbol")
		lot, err := strconv.ParseFloat(r.FormValue("lot"), 64)
		if err != nil {
			http.Error(w, "Invalid lot value", http.StatusBadRequest)
			return
		}
		averagePrice, err := strconv.ParseFloat(r.FormValue("average_price"), 64)
		if err != nil {
			http.Error(w, "Invalid average price value", http.StatusBadRequest)
			return
		}

		q, err := quote.Get(symbol)
		if err != nil {
			http.Error(w, "Error fetching quote data", http.StatusInternalServerError)
			return
		}

		shortName := q.ShortName

		// Check if the symbol already exists in the portfolio
		var existingLot float64
		var existingAveragePrice float64
		err = db.QueryRow("SELECT lot, average_price FROM portfolios WHERE username = ? AND short_name = ?", username, shortName).Scan(&existingLot, &existingAveragePrice)
		if err == nil {
			// Update the existing symbol
			newLot := existingLot + lot
			newAveragePrice := ((existingLot * existingAveragePrice) + (lot * averagePrice)) / newLot
			_, err = db.Exec("UPDATE portfolios SET lot = ?, average_price = ?, total_invested = ? WHERE username = ? AND short_name = ?", newLot, newAveragePrice, newLot*newAveragePrice, username, shortName)
			if err != nil {
				http.Error(w, "Error updating existing symbol in portfolio", http.StatusInternalServerError)
				return
			}
		} else {
			// Insert a new symbol
			totalInvested := lot * averagePrice
			_, err = db.Exec("INSERT INTO portfolios (username, symbol, short_name, lot, average_price, total_invested) VALUES (?, ?, ?, ?, ?, ?)", username, symbol, shortName, lot, averagePrice, totalInvested)
			if err != nil {
				http.Error(w, "Error adding symbol to portfolio", http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/portfolio", http.StatusSeeOther)
		return
	}

	tmpl, err := template.ParseFiles("templates/add_symbol.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func editSymbolHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	if r.Method == "POST" {
		id := r.FormValue("id")
		lot, err := strconv.ParseFloat(r.FormValue("lot"), 64)
		if err != nil {
			http.Error(w, "Invalid lot value", http.StatusBadRequest)
			return
		}
		averagePrice, err := strconv.ParseFloat(r.FormValue("average_price"), 64)
		if err != nil {
			http.Error(w, "Invalid average price value", http.StatusBadRequest)
			return
		}

		totalInvested := lot * averagePrice

		_, err = db.Exec("UPDATE portfolios SET lot = ?, average_price = ?, total_invested = ? WHERE id = ? AND username = ?", lot, averagePrice, totalInvested, id, username)
		if err != nil {
			http.Error(w, "Error updating symbol in portfolio", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/portfolio", http.StatusSeeOther)
		return
	}

	id := r.URL.Query().Get("id")
	row := db.QueryRow("SELECT id, symbol, lot, average_price FROM portfolios WHERE id = ? AND username = ?", id, username)
	var symbol string
	var lot float64
	var averagePrice float64

	err = row.Scan(&id, &symbol, &lot, &averagePrice)
	if err != nil {
		http.Error(w, "Error fetching symbol data", http.StatusInternalServerError)
		return
	}

	data := struct {
		ID           string
		Symbol       string
		Lot          float64
		AveragePrice float64
	}{
		ID:           id,
		Symbol:       symbol,
		Lot:          lot,
		AveragePrice: averagePrice,
	}

	tmpl, err := template.ParseFiles("templates/edit_symbol.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func deleteSymbolHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	id := r.URL.Query().Get("id")
	_, err = db.Exec("DELETE FROM portfolios WHERE id = ? AND username = ?", id, username)
	if err != nil {
		http.Error(w, "Error deleting symbol from portfolio", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portfolio", http.StatusSeeOther)
}

type PortfolioData struct {
	ID            int
	Symbol        string
	ShortName     string
	Lot           float64
	AveragePrice  float64
	TotalInvested float64
	CurrentPrice  float64
	PnL           float64
	Percentage    float64
}

func portfolioHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	rows, err := db.Query("SELECT id, symbol, short_name, lot, average_price FROM portfolios WHERE username = ?", username)
	if err != nil {
		http.Error(w, "Error fetching portfolio data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var portfolio []PortfolioData
	var totalInvestedSum float64

	for rows.Next() {
		var id int
		var symbol, shortName string
		var lot float64
		var averagePrice float64
		err := rows.Scan(&id, &symbol, &shortName, &lot, &averagePrice)
		if err != nil {
			http.Error(w, "Error scanning portfolio data", http.StatusInternalServerError)
			return
		}

		totalInvested := lot * averagePrice
		totalInvestedSum += totalInvested

		q, err := quote.Get(symbol)
		if err != nil {
			http.Error(w, "Error fetching quote data", http.StatusInternalServerError)
			return
		}

		currentPrice := q.RegularMarketPrice
		pnl := lot * (currentPrice - averagePrice)

		portfolio = append(portfolio, PortfolioData{
			ID:            id,
			Symbol:        symbol,
			ShortName:     shortName,
			Lot:           lot,
			AveragePrice:  averagePrice,
			TotalInvested: totalInvested,
			CurrentPrice:  currentPrice,
			PnL:           math.Round(pnl*100) / 100, // Round to 2 decimal places
		})
	}

	for i := range portfolio {
		portfolio[i].Percentage = (portfolio[i].TotalInvested / totalInvestedSum) * 100
	}

	tmpl, err := template.ParseFiles("templates/portfolio.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, portfolio)
	if err != nil {
		http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func userProfileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	if r.Method == "POST" {
		email := r.FormValue("email")
		phone := r.FormValue("phone")
		birthdate := r.FormValue("birthdate")
		investmentProfile := r.FormValue("investment_profile")
		investmentGoals, _ := strconv.ParseFloat(r.FormValue("investment_goals"), 64)
		riskTolerance, _ := strconv.ParseFloat(r.FormValue("risk_tolerance"), 64)
		favSymbol := r.FormValue("fav_symbol")
		wiseWord := r.FormValue("wise_word")

		_, err = db.Exec(`UPDATE users 
            SET email = ?, phone = ?, birthdate = ?, investment_profile = ?, 
            investment_goals = ?, risk_tolerance = ?, fav_symbol = ?, wise_word = ?
            WHERE username = ?`, email, phone, birthdate, investmentProfile, investmentGoals, riskTolerance, favSymbol, wiseWord, username)
		if err != nil {
			log.Println("Error updating user profile:", err)
			http.Error(w, "Error updating user profile", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/user_account", http.StatusSeeOther)
		return
	}

	var user struct {
		Username          string
		Email             sql.NullString
		Phone             sql.NullString
		Birthdate         sql.NullString
		InvestmentProfile sql.NullString
		InvestmentGoals   sql.NullFloat64
		RiskTolerance     sql.NullFloat64
		FavSymbol         sql.NullString
		WiseWord          sql.NullString
	}

	err = db.QueryRow(`SELECT username, 
        email, 
        phone, 
        birthdate, 
        investment_profile, 
        investment_goals, 
        risk_tolerance, 
        fav_symbol, 
        wise_word 
        FROM users WHERE username = ?`, username).Scan(
		&user.Username, &user.Email, &user.Phone, &user.Birthdate, &user.InvestmentProfile, &user.InvestmentGoals, &user.RiskTolerance, &user.FavSymbol, &user.WiseWord)
	if err != nil {
		log.Println("Error fetching user data:", err)
		http.Error(w, "Error fetching user data", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username          string
		Email             string
		Phone             string
		Birthdate         string
		InvestmentProfile string
		InvestmentGoals   float64
		RiskTolerance     float64
		FavSymbol         string
		WiseWord          string
	}{
		Username:          user.Username,
		Email:             user.Email.String,
		Phone:             user.Phone.String,
		Birthdate:         user.Birthdate.String,
		InvestmentProfile: user.InvestmentProfile.String,
		InvestmentGoals:   user.InvestmentGoals.Float64,
		RiskTolerance:     user.RiskTolerance.Float64,
		FavSymbol:         user.FavSymbol.String,
		WiseWord:          user.WiseWord.String,
	}

	tmpl, err := template.ParseFiles("templates/user_account.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("templates/index.html")
		if err != nil {
			http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	})

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/portfolio", portfolioHandler)
	http.HandleFunc("/add_symbol", addSymbolHandler)
	http.HandleFunc("/edit_symbol", editSymbolHandler)
	http.HandleFunc("/delete_symbol", deleteSymbolHandler)
	http.HandleFunc("/user_account", userProfileHandler)

	http.HandleFunc("/quote", quoteHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
