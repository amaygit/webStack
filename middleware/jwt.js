import jwt from "jsonwebtoken";
import createError from "../utils/createError.js";

export const verifyToken = (req, res, next) => {
  const token = req.cookies.accessToken;
  if (!token) return next(createError(401,"You are not authenticated!"))


  jwt.verify(token, "586ab63d048a1d691a4c4693a", async (err, payload) => {
    if (err) return next(createError(403,"Token is not valid!"))
    req.userId = payload.id;
    req.isSeller = payload.isSeller;
    next()
  });
};
