import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

// Midleware för att verifiera JWT-token

export default function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  //   const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ error: "JWT-token saknas." });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (error, payload) => {
    // Om verifieringen misslyckas
    if (error) {
      return res
        .status(403)
        .json({ error: "JWT-token är ogiltig eller har gått ur." });
    }

    // Om verifieringen gick bra(inget err) så får vi tillbaka en payload, och vi sparar den i req objectet.
    req.user = payload;

    next();
  });
}
