const express = require("express")
const mysql = require("mysql2")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

app.use(cors({
  origin: true,
  credentials: true
}))

app.use(express.json())
app.use(express.static("public"))

app.use(session({
  secret: "aditya-super-secret-key-2026-very-secure",
  resave: false,
  saveUninitialized: false
}))

// DATABASE
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "crud_db"
})

db.connect(err => {
  if (err) console.log(err)
  else console.log("✅ Database connected")
})

// REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body

  db.query("SELECT * FROM auth_users WHERE username = ?", [username], async (err, result) => {
    if (err) return res.status(500).send(err)
    if (result.length > 0) return res.json({ success: false })

    const hash = await bcrypt.hash(password, 10)

    db.query(
      "INSERT INTO auth_users (username, password) VALUES (?, ?)",
      [username, hash],
      (err) => {
        if (err) return res.status(500).send(err)
        res.json({ success: true })
      }
    )
  })
})

// LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body

  db.query("SELECT * FROM auth_users WHERE username = ?", [username], async (err, result) => {
    if (err) return res.status(500).send(err)
    if (result.length === 0) return res.json({ success: false })

    const match = await bcrypt.compare(password, result[0].password)

    if (match) {
      req.session.user = username
      res.json({ success: true })
    } else {
      res.json({ success: false })
    }
  })
})

// CHECK AUTH
app.get("/check-auth", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user })
  } else {
    res.json({ loggedIn: false })
  }
})

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy()
  res.json({ success: true })
})

// CRUD
app.post("/users", isAuth, (req, res) => {
  const { name, email } = req.body

  db.query("INSERT INTO users (name,email) VALUES (?,?)", [name, email], (err) => {
    if (err) return res.status(500).send(err)
    res.send("OK")
  })
})

app.get("/users", isAuth, (req, res) => {
  db.query("SELECT * FROM users", (err, data) => {
    if (err) return res.status(500).send(err)
    res.json(data)
  })
})

app.delete("/users/:id", isAuth, (req, res) => {
  db.query("DELETE FROM users WHERE id=?", [req.params.id], (err) => {
    if (err) return res.status(500).send(err)
    res.send("OK")
  })
})

app.put("/users/:id", isAuth, (req, res) => {
  const { name, email } = req.body

  db.query("UPDATE users SET name=?,email=? WHERE id=?", [name, email, req.params.id], (err) => {
    if (err) return res.status(500).send(err)
    res.send("OK")
  })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log("🚀 Server running"))

function isAuth(req, res, next) {
  if (req.session.user) {
    next()
  } else {
    res.status(401).json({ message: "Unauthorized" })
  }
}

