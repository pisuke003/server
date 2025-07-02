import jwt from 'jsonwebtoken';

const userAuth = (req, res, next) => {
  const { token } = req.cookies;
  // console.log("Cookies received:", req.cookies);

  if (!token) {
    return res.status(401).json({ message: "Unauthorized access. Token missing." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // decode the token
    req.userId = decoded.userId; //  extract userId
    next();
  } catch (error) {
    console.error("JWT verification failed:", error.message);
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

export default userAuth;
