package main

import (
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"sort"

	"github.com/piquette/finance-go/equity"
	"github.com/piquette/finance-go/quote"
	"github.com/sirupsen/logrus"
)

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

	switch choice {
	case "1":
		resultData, err = displaySymbolViewer(symbol)
	case "2":
		resultData, err = displayFibonacciLevels(symbol)
	default:
		http.Error(w, "Invalid choice", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Error processing request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/result.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, resultData)
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

	http.HandleFunc("/quote", quoteHandler)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
