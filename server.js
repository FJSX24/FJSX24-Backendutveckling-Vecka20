import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(express.json());

// Skapa en lokal "db" med användare
let users = [];

// Registrera en använder (med bcrypt hashat och saltat lösenord)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const saltRounds = 10;

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  users.push({ username, password: hashedPassword });

  res.status(201).json({ message: "Användare registrerad." });
});

// Logga in route med JWT och bcrypt verifiering
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  if (!user)
    return res
      .status(401)
      .json({ error: "Användaren finns inte i databasen." });

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.status(401).json({ error: "Fel lösenord." });
  }

  //   Skapa en token till denna användare för att vi har hittat hen i db och lösenordet stämmer
  const token = jwt.sign({ username }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ token });
});

// En skydda route

// En public route

// Lyssna på servern
