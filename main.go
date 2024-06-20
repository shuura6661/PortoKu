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
	"strings"
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

func formatNumber(value float64) string {
	return fmt.Sprintf("$%s", commaFormat(value))
}

func commaFormat(value float64) string {
	parts := strings.Split(fmt.Sprintf("%.2f", value), ".")
	integerPart := parts[0]
	decimalPart := parts[1]

	var result strings.Builder
	if len(integerPart) > 0 && integerPart[0] == '-' {
		result.WriteByte('-')
		integerPart = integerPart[1:]
	}

	for i, digit := range integerPart {
		if i > 0 && (len(integerPart)-i)%3 == 0 {
			result.WriteByte(',')
		}
		result.WriteRune(digit)
	}

	if decimalPart != "" {
		result.WriteByte('.')
		result.WriteString(decimalPart)
	}

	return result.String()
}

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
	Symbol                     string
	CurrentPrice               float64
	FiftyTwoWeekHigh           float64
	FiftyTwoWeekLow            float64
	MarketCap                  float64
	RegularMarketDayLow        float64
	RegularMarketDayHigh       float64
	RegularMarketChangePercent float64
	RegularMarketVolume        int64
	FibonacciLevels            []FibLevel
	TradeIdeas                 []TradeIdea
	ChartHTML                  template.HTML
	Zone                       string // Add this field to store the zone information
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
		Symbol:                     q.ShortName,
		CurrentPrice:               currentPrice,
		FiftyTwoWeekHigh:           q.FiftyTwoWeekHigh,
		FiftyTwoWeekLow:            q.FiftyTwoWeekLow,
		MarketCap:                  float64(e.MarketCap),
		RegularMarketDayLow:        q.RegularMarketDayLow,
		RegularMarketDayHigh:       q.RegularMarketDayHigh,
		RegularMarketChangePercent: q.RegularMarketChangePercent,
		RegularMarketVolume:        int64(q.RegularMarketVolume),
		ChartHTML:                  renderChart(smbl),
	}, nil
}

func displayFibonacciLevels(smbl string) (ResultData, error) {
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
		Symbol:                     q.ShortName,
		CurrentPrice:               currentPrice,
		FiftyTwoWeekHigh:           high,
		FiftyTwoWeekLow:            low,
		MarketCap:                  float64(e.MarketCap),
		RegularMarketDayLow:        q.RegularMarketDayLow,
		RegularMarketDayHigh:       q.RegularMarketDayHigh,
		RegularMarketChangePercent: q.RegularMarketChangePercent,
		RegularMarketVolume:        int64(q.RegularMarketVolume),
		FibonacciLevels:            fibSlice,
		TradeIdeas:                 tradeIdeas,
		ChartHTML:                  renderChart(smbl),
		Zone:                       zone, // Include the zone information in the result
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
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := cookie.Value
	log.Println("Username from cookie:", username)

	var user struct {
		Username        string
		InvestmentGoals sql.NullFloat64
		WiseWord        sql.NullString
		FavSymbol       sql.NullString
	}

	err = db.QueryRow(`SELECT username, investment_goals, wise_word, fav_symbol FROM users WHERE username = ?`, username).Scan(
		&user.Username, &user.InvestmentGoals, &user.WiseWord, &user.FavSymbol)
	if err != nil {
		log.Println("Error fetching user data:", err)
		http.Error(w, "Error fetching user data", http.StatusInternalServerError)
		return
	}

	// Update portfolio data before retrieving it
	err = updatePortfolioData(username)
	if err != nil {
		http.Error(w, "Error updating portfolio data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Split the favorite symbols
	favSymbols := split(user.FavSymbol.String, ",")

	var favoriteSymbols []ResultData
	for _, sym := range favSymbols {
		result, err := displaySymbolViewer(sym)
		if err == nil {
			favoriteSymbols = append(favoriteSymbols, result)
		}
	}

	var totalInvested float64
	var totalPnL float64
	rows, err := db.Query("SELECT total_invested, pnl FROM portfolios WHERE username = ?", username)
	if err != nil {
		log.Println("Error fetching portfolio data:", err)
		http.Error(w, "Error fetching portfolio data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var totalInvestedVal, pnlVal float64
		err := rows.Scan(&totalInvestedVal, &pnlVal)
		if err != nil {
			log.Println("Error scanning portfolio data:", err)
			http.Error(w, "Error scanning portfolio data", http.StatusInternalServerError)
			return
		}
		log.Printf("Fetched: total_invested = %f, pnl = %f\n", totalInvestedVal, pnlVal)
		totalInvested += totalInvestedVal
		totalPnL += pnlVal
	}

	log.Printf("Total Invested: %f, Total PnL: %f\n", totalInvested, totalPnL)

	data := struct {
		Username        string
		TotalInvested   float64
		PnL             float64
		InvestmentGoals float64
		WiseWord        string
		FavoriteSymbols []ResultData
	}{
		Username:        user.Username,
		TotalInvested:   totalInvested,
		PnL:             totalPnL,
		InvestmentGoals: user.InvestmentGoals.Float64,
		WiseWord:        user.WiseWord.String,
		FavoriteSymbols: favoriteSymbols,
	}

	funcMap := template.FuncMap{
		"subtract": func(a, b float64) float64 {
			return a - b
		},
		"formatNumber": formatNumber, // Add the formatNumber function to the template FuncMap
	}

	tmpl, err := template.New("dashboard.html").Funcs(funcMap).ParseFiles("templates/dashboard.html")
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

func updatePortfolioData(username string) error {
	rows, err := db.Query("SELECT id, symbol, lot, average_price FROM portfolios WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("error fetching portfolio data: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var symbol string
		var lot float64
		var averagePrice float64
		err := rows.Scan(&id, &symbol, &lot, &averagePrice)
		if err != nil {
			return fmt.Errorf("error scanning portfolio data: %w", err)
		}

		q, err := quote.Get(symbol)
		if err != nil {
			return fmt.Errorf("error fetching quote data: %w", err)
		}

		currentPrice := q.RegularMarketPrice
		pnl := lot * (currentPrice - averagePrice)

		_, err = db.Exec("UPDATE portfolios SET current_price = ?, pnl = ? WHERE id = ?", currentPrice, pnl, id)
		if err != nil {
			return fmt.Errorf("error updating portfolio data: %w", err)
		}
	}

	return nil
}

func portfolioHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := cookie.Value

	// Update portfolio data before retrieving it
	err = updatePortfolioData(username)
	if err != nil {
		http.Error(w, "Error updating portfolio data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rows, err := db.Query("SELECT id, symbol, short_name, lot, average_price, current_price, pnl FROM portfolios WHERE username = ?", username)
	if err != nil {
		http.Error(w, "Error fetching portfolio data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var portfolio []PortfolioData
	var totalInvestedSum float64
	var totalPnL float64

	for rows.Next() {
		var id int
		var symbol, shortName string
		var lot float64
		var averagePrice float64
		var currentPrice float64
		var pnl float64
		err := rows.Scan(&id, &symbol, &shortName, &lot, &averagePrice, &currentPrice, &pnl)
		if err != nil {
			http.Error(w, "Error scanning portfolio data", http.StatusInternalServerError)
			return
		}

		totalInvested := lot * averagePrice
		totalInvestedSum += totalInvested
		totalPnL += pnl

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

	funcMap := template.FuncMap{
		"formatNumber": formatNumber, // Add the formatNumber function to the template FuncMap
	}

	tmpl, err := template.New("portfolio.html").Funcs(funcMap).ParseFiles("templates/portfolio.html")
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
	currentUsername := cookie.Value

	if r.Method == "POST" {
		newUsername := r.FormValue("username")
		email := r.FormValue("email")
		phone := r.FormValue("phone")
		birthdate := r.FormValue("birthdate")
		investmentProfile := r.FormValue("investment_profile")
		investmentGoals, _ := strconv.ParseFloat(r.FormValue("investment_goals"), 64)
		riskTolerance, _ := strconv.ParseFloat(r.FormValue("risk_tolerance"), 64)
		favSymbol := r.FormValue("fav_symbol")
		wiseWord := r.FormValue("wise_word")

		// Start a transaction
		tx, err := db.Begin()
		if err != nil {
			log.Println("Error starting transaction:", err)
			http.Error(w, "Error updating user profile", http.StatusInternalServerError)
			return
		}

		// Temporarily remove foreign key constraint
		_, err = tx.Exec("SET FOREIGN_KEY_CHECKS=0")
		if err != nil {
			tx.Rollback()
			log.Println("Error disabling foreign key checks:", err)
			http.Error(w, "Error updating user profile", http.StatusInternalServerError)
			return
		}

		// Update the username in the portfolios table
		_, err = tx.Exec(`UPDATE portfolios SET username = ? WHERE username = ?`, newUsername, currentUsername)
		if err != nil {
			tx.Rollback()
			log.Println("Error updating portfolios table:", err)
			http.Error(w, "Error updating user profile", http.StatusInternalServerError)
			return
		}

		// Update the user profile in the users table
		_, err = tx.Exec(`UPDATE users 
            SET username = ?, email = ?, phone = ?, birthdate = ?, investment_profile = ?, 
            investment_goals = ?, risk_tolerance = ?, fav_symbol = ?, wise_word = ?
            WHERE username = ?`, newUsername, email, phone, birthdate, investmentProfile, investmentGoals, riskTolerance, favSymbol, wiseWord, currentUsername)
		if err != nil {
			tx.Rollback()
			log.Println("Error updating users table:", err)
			http.Error(w, "Error updating user profile", http.StatusInternalServerError)
			return
		}

		// Re-enable foreign key constraint
		_, err = tx.Exec("SET FOREIGN_KEY_CHECKS=1")
		if err != nil {
			tx.Rollback()
			log.Println("Error enabling foreign key checks:", err)
			http.Error(w, "Error updating user profile", http.StatusInternalServerError)
			return
		}

		// Commit the transaction
		err = tx.Commit()
		if err != nil {
			log.Println("Error committing transaction:", err)
			http.Error(w, "Error updating user profile", http.StatusInternalServerError)
			return
		}

		// Update the username cookie
		http.SetCookie(w, &http.Cookie{
			Name:  "username",
			Value: newUsername,
			Path:  "/",
			// Secure: true, // Uncomment if using HTTPS
			HttpOnly: true,
		})
		log.Println("Updated cookie for username:", newUsername)

		// Redirect to the user account page with a success message
		http.Redirect(w, r, "/user_account?updated=true", http.StatusSeeOther)
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
        FROM users WHERE username = ?`, currentUsername).Scan(
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

func split(input string, delimiter string) []string {
	if input == "" {
		return []string{}
	}
	return strings.Split(input, delimiter)
}
