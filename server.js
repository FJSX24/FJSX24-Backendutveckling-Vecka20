import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// Skapa en enkel "usertabell" och "databas" bara för demo skull
const users = [
  { id: 1, username: "mandus", password: "mandus123", role: "admin" },
  { id: 2, username: "Frank", password: "Frank123", role: "user" },
];

// Login route
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Kontrollera användarens inloggningsuppgifter
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user)
    return res.status(401).json({ error: "Fel användarnamn eller lösenord" });

  //   Skapa JWT token till användare med användarens id och roll som payload
  const token = jwt.sign(
    { userId: user.id, role: user.role, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  console.log("token: ", token);

  // Skicka tillbaka JWT till klienten
  res.json({ token });
});

// Skyddad route som kräver en giltig JWT-token i headern, vi testar att göra det utan middleware
app.get("/secret", (req, res) => {
  const authHeader = req.headers["authorization"];
  // const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "JWT-token saknas." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    res.status(200).json({
      message: "Du är inloggad och kan se den hära skyddade routen.",
      user: payload, //Inehåller data som userId, role, username osv...
    });
  } catch (error) {
    // om token är ogiltig, manipulera eller gått ut så fångas felet här i catch
    res.status(403).json({ error: "JWT-token är ogiltig!" });
  }
});

// Route för dem med giltigt token och rolen "admin"
app.get("/secret/admins", (req, res) => {
  //   const authHeader = req.headers["authorization"];
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "JWT-token saknas." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // Kontrollera om användaren är admin
    if (payload.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Du har inte behörighet att komma åt denna route." });
    }

    res.status(200).json({
      message:
        "Välkommen, admin! Du har tillgång till denna skyddade admin-route.",
      user: payload, //Inehåller data som userId, role, username osv...
    });
  } catch (error) {
    // om token är ogiltig, manipulera eller gått ut så fångas felet här i catch
    res.status(403).json({ error: "JWT-token är ogiltig!" });
  }
});

// Lyssna på servern
app.listen(5000, () => {
  console.log("server running on http://localhost:5000");
});
