const express = require("express")
const mysql = require("mysql2/promise")
const cors = require("cors")
const bcrypt = require("bcrypt")
const session = require("express-session")

const app = express()

// 🔐 TRUST PROXY (WAJIB UNTUK VERCEL/RAILWAY)
app.set("trust proxy", 1)

// 🔐 CORS
app.use(cors({
  origin: "https://website-aditya-one.vercel.app",
  credentials: true
}))

app.use(express.json())

// 🔐 SESSION
app.use(session({
  secret: process.env.SESSION_SECRET || "secret-key",
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 1000 * 60 * 60 * 24
  }
}))

// 🗄 DATABASE
const db = mysql.createPool({
  uri: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

// ================= MIDDLEWARE =================
function isAuth(req, res, next){
  if(!req.session.user){
    return res.status(401).json({ error: "Unauthorized" })
  }
  next()
}

function isAdmin(req, res, next){
  if(!req.session.user || req.session.user.role !== "admin"){
    return res.status(403).json({ error: "Forbidden" })
  }
  next()
}

// ================= ME =================
app.get("/me", (req, res) => {
  if(req.session.user){
    res.json({
      loggedIn: true,
      user: req.session.user
    })
  }else{
    res.json({ loggedIn: false })
  }
})

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  try{
    const { username, password } = req.body

    if(!username || !password){
      return res.json({ success:false, message:"Data tidak lengkap" })
    }

    if(password.length < 6){
      return res.json({ success:false, message:"Minimal 6 karakter" })
    }

    const hasHuruf = /[A-Za-z]/.test(password)
    const hasAngka = /[0-9]/.test(password)

    if(!hasHuruf || !hasAngka){
      return res.json({ success:false, message:"Harus huruf & angka" })
    }

    const [cek] = await db.query(
      "SELECT * FROM auth_users WHERE username=?",
      [username]
    )

    if(cek.length > 0){
      return res.json({ success:false, message:"Username sudah ada" })
    }

    const hash = await bcrypt.hash(password,10)

    await db.query(
      "INSERT INTO auth_users (username,password) VALUES (?,?)",
      [username,hash]
    )

    res.json({ success:true })

  }catch(err){
    console.error(err)
    res.status(500).json({ success:false })
  }
})

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  try{
    const { username, password } = req.body

    if(!username || !password){
      return res.json({ success:false })
    }

    const [user] = await db.query(
      "SELECT * FROM auth_users WHERE username=?",
      [username]
    )

    if(user.length === 0){
      return res.json({ success:false })
    }

    const match = await bcrypt.compare(password, user[0].password)

    if(!match){
      return res.json({ success:false })
    }

    req.session.user = {
      username: user[0].username,
      role: user[0].role || "user"
    }

    res.json({ success:true })

  }catch(err){
    console.error(err)
    res.status(500).json({ success:false })
  }
})

// ================= CHANGE PASSWORD =================
app.post("/change-password", async (req, res) => {
  try{
    if(!req.session.user){
      return res.status(401).json({ error:"Unauthorized" })
    }

    const { oldPassword, newPassword } = req.body

    if(!oldPassword || !newPassword){
      return res.json({ success:false, message:"Data kosong" })
    }

    const [user] = await db.query(
      "SELECT * FROM auth_users WHERE username=?",
      [req.session.user.username]
    )

    const match = await bcrypt.compare(oldPassword, user[0].password)

    if(!match){
      return res.json({ success:false, message:"Password lama salah" })
    }

    const hash = await bcrypt.hash(newPassword,10)

    await db.query(
      "UPDATE auth_users SET password=? WHERE username=?",
      [hash, req.session.user.username]
    )

    res.json({ success:true })

  }catch(err){
    console.error(err)
    res.status(500).json({ success:false })
  }
})

// ================= STATS (🔥 FIX UTAMA) =================
app.get("/stats", isAuth, async (req, res) => {
  try{
    const [users] = await db.query(
      "SELECT COUNT(*) as total FROM users"
    )

    const [accounts] = await db.query(
      "SELECT COUNT(*) as total FROM auth_users"
    )

    res.json({
      totalUsers: users[0].total,
      totalAccounts: accounts[0].total
    })

  }catch(err){
    console.error(err)
    res.status(500).json({ error:"Server error" })
  }
})

// ================= USERS =================
app.get("/users", isAuth, async (req, res) => {
  try{
    const [data] = await db.query("SELECT * FROM users ORDER BY id DESC")
    res.json(data)
  }catch{
    res.status(500).json({ error:"Server error" })
  }
})

app.post("/users", isAuth, isAdmin, async (req, res) => {
  try{
    const { name, email } = req.body

    if(!name || !email){
      return res.status(400).json({ error:"Data kosong" })
    }

    await db.query(
      "INSERT INTO users (name,email) VALUES (?,?)",
      [name,email]
    )

    res.json({ success:true })

  }catch{
    res.status(500).json({ error:"Server error" })
  }
})

app.delete("/users/:id", isAuth, isAdmin, async (req, res) => {
  try{
    await db.query("DELETE FROM users WHERE id=?", [req.params.id])
    res.json({ success:true })
  }catch{
    res.status(500).json({ error:"Server error" })
  }
})

app.put("/users/:id", isAuth, isAdmin, async (req, res) => {
  try{
    const { name, email } = req.body

    await db.query(
      "UPDATE users SET name=?, email=? WHERE id=?",
      [name,email,req.params.id]
    )

    res.json({ success:true })

  }catch{
    res.status(500).json({ error:"Server error" })
  }
})

// ================= LOGOUT =================
app.get("/logout", (req, res) => {
  req.session.destroy(()=>{
    res.clearCookie("connect.sid")
    res.json({ success:true })
  })
})

// ================= START =================
app.listen(process.env.PORT || 3000, () => {
  console.log("Server jalan...")
})