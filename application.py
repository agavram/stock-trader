import os, requests

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    stocks = db.execute("SELECT * FROM stocks WHERE user_id = :uid", uid=session["user_id"])
    info=[]
    numSum = 0.0;
    for i in range(len(stocks)):
        r = lookup(stocks[i]["symbol"])
        info.append([])
        numSum += (float(r["price"]) * stocks[i]["shares"])
        info[i].append(r["price"])
        info[i].append(r["name"])
    balance = db.execute("SELECT cash FROM users WHERE id = :uid", uid=session["user_id"])[0]["cash"]
    numSum += balance
    return render_template("index.html", stocks=stocks, info=info, balance=balance, numSum=numSum)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Must enter a symbol")
        r = lookup(request.form.get("symbol"))
        if not r:
            return apology("Must enter a proper symbol")
        if not request.form.get("shares"):
            return apology("Must enter a number of shares")
        if int(request.form.get("shares")) < 1:
            return apology("Must buy at least one share")
        
        price = r["price"] * int(request.form.get("shares"))
        user_id= session["user_id"]
        balance = int(db.execute("SELECT cash FROM users WHERE id = :uid", uid=user_id)[0]["cash"])
        if (price > balance):
            return apology("Not enough money to purchase shares")
        db.execute("UPDATE users SET cash = :cash WHERE id = :uid", cash=(balance - price), uid=user_id)
        currShares = db.execute("SELECT shares FROM stocks WHERE user_id = :uid AND symbol = :symbol", uid=user_id, symbol=request.form.get("symbol"))
        if (currShares):
            currShares = int(currShares[0]["shares"])
            db.execute("UPDATE stocks SET shares = :shares WHERE user_id = :uid AND symbol = :symbol", shares=currShares + int(request.form.get("shares")), uid=user_id, symbol=request.form.get("symbol"))
        else:
            db.execute("INSERT INTO stocks(user_id, symbol, shares) VALUES(:user_id, :symbol, :shares)", user_id=user_id, symbol=request.form.get("symbol"), shares=int(request.form.get("shares")))
        return redirect("/")
    else:
        balance = db.execute("SELECT cash FROM users WHERE id = :uid", uid=session["user_id"])[0]["cash"]
        return render_template("buy.html", balance=balance)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username").lower())

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["POST", "GET"])
def register():
    """Register user"""
    
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif not request.form.get("confirmation"):
            return apology("must enter password confirmation", 403)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 403)
        username = request.form.get("username").lower()
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)
        if rows:
            return apology("username is already taken", 403)
        
        db.execute("INSERT INTO users(username, hash) VALUES (:username, :pwhash)", username=username, pwhash=generate_password_hash(request.form.get("password")))
        return redirect("/")
    else:
        return render_template("register.html")    
    
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        response = lookup(request.form.get("symbol"))
        if (response):
            return render_template("quoted.html", response=response)
        else:
            return apology("there was an error fetching the stock price")
    return render_template("quote.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        if (not request.form.get("symbol")):
            return apology("Must select a stock symbol")
        if (not request.form.get("shares")):
            return apology("Must select a number of shares greater than zero")
        sellShares = int(request.form.get("shares"))
        if (sellShares < 1):
            return apology("Must select a number of shares greater than zero")
        currShares = db.execute("SELECT shares FROM stocks WHERE symbol = :symbol AND user_id = :uid", symbol=request.form.get("symbol"), uid=session["user_id"])[0]["shares"]
        if (sellShares > currShares):
            return apology("You cannot sell more shares than you have")
        sell = lookup(request.form.get("symbol"))["price"]
        sell *= sellShares
        if (currShares - sellShares == 0):
            db.execute("DELETE FROM stocks WHERE symbol = :symbol AND user_id = :uid", symbol=request.form.get("symbol"), uid=session["user_id"])
        else:
            db.execute("UPDATE stocks SET shares = :shares WHERE symbol = :symbol AND user_id = :uid", shares=(currShares - sellShares), symbol=request.form.get("symbol"), uid=session["user_id"])
        balance = int(db.execute("SELECT cash FROM users WHERE id = :uid", uid=session["user_id"])[0]["cash"])
        db.execute("UPDATE users SET cash = :cash WHERE id = :uid", cash=(balance+sell), uid=session["user_id"])
        return redirect("/")
    stocks = db.execute("SELECT * FROM stocks WHERE user_id = :user_id", user_id=session["user_id"])
    balance = db.execute("SELECT cash FROM users WHERE id = :uid", uid=session["user_id"])[0]["cash"]
    return render_template("sell.html", stocks=stocks)

@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        if not request.form.get("password"):
            return apology("Must enter your current password")
        if not request.form.get("new-password"):
            return apology("Must enter a new password")
        if not request.form.get("confirmation"):
            return apology("Must enter password confirmation")
        if request.form.get("new-password") != request.form.get("confirmation"):
            return apology("New password must match confirmation")
        currPassword = db.execute("SELECT hash FROM users WHERE id = :uid", uid=session["user_id"])
        if not check_password_hash(currPassword[0]["hash"], request.form.get("password")):
            return apology("Incorrect current password was entered")
        db.execute("UPDATE users SET hash = :pwhash WHERE id = :uid", pwhash=generate_password_hash(request.form.get("confirmation")), uid=session["user_id"])
        return redirect("/")
    else:
        return render_template("password.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
