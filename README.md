# PortoKu Dashboard

This project is a Portfolio Invesment application that allows users to manage their portfolios, view symbol market data, and get investment insights. The application is built using Go and MySQL, and it provides a user-friendly interface for tracking investments.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)

## Features

- User registration and login
- Portfolio management
- Viewing stock market data
- Symbol viewer and AI features for Fibonacci levels
- Responsive and user-friendly interface

## Installation

### Prerequisites

- Go (version 1.15 or higher)
- MySQL (version 5.7 or higher)

### Steps

1. Clone the repository:

   ```sh
   git clone https://github.com/shuura6661/PortoKu.git
   cd PortoKu
2. Install dependencies:
   ```sh
   go mod tidy
3. Set up the MySQL database:
   - Create a new MySQL database:
     ```sh
     CREATE DATABASE stock_trader;
   - Create a new MySQL database:
     ```sh
     mysql -u yourusername -p stock_trader < schema.sql
4. Update the database connection string in main.go:
   ```sh
   db, err = sql.Open("mysql", "yourusername:yourpassword@tcp(localhost:3306)/stock_trader")
5. Run the application:
   ```sh
   go run main.go
6. Open your web browser and navigate to http://localhost:8080.


## Usage
### User Registration and Login
- Register a new account by navigating to the registration page.
- Log in with your credentials to access the dashboard.
  
### Portfolio Management
- Add, edit, and delete stocks in your portfolio.
- View the total invested amount and returns.
  
### Market Overview
- View your favorite stock symbols along with their current market data.
- Use the symbol viewer and AI features for Fibonacci levels to get investment insights.

## Project Structure
```sh
stock-trader-dashboard/
│
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── user_account.html
│   ├── portfolio.html
│   ├── add_symbol.html
│   ├── edit_symbol.html
├── static/
│   ├── styles.css
│   ├── scripts.js
├── main.go
├── schema.sql
└── README.md
```

## Database Schema
### Users Table
```sh
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(20),
    birthdate DATE,
    investment_profile ENUM('Conservative', 'Moderate', 'Aggressive'),
    investment_goals DECIMAL(10, 2),
    risk_tolerance DECIMAL(5, 2),
    fav_symbol VARCHAR(255),
    wise_word TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```
### Portfolios Table
```sh
CREATE TABLE portfolios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    symbol VARCHAR(255),
    short_name VARCHAR(255),
    lot DECIMAL(10, 2),
    average_price DECIMAL(10, 2),
    total_invested DECIMAL(10, 2),
    current_price DECIMAL(10, 2),
    pnl DECIMAL(10, 2),
    FOREIGN KEY (username) REFERENCES users(username)
);

```
