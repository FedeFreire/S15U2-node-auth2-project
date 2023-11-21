const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const bcrypt = require("bcryptjs");
const Users = require("../users/users-model");
const jwt = require("jsonwebtoken");
const db = require("../../data/db-config.js");

const { BCRYPT_ROUNDS, JWT_SECRET } = require("../secrets"); // use this secret!

// router.post("/register", validateRoleName, (req, res, next) => {
//   /**
//     [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

//     response:
//     status 201
//     {
//       "user"_id: 3,
//       "username": "anna",
//       "role_name": "angel"
//     }
//    */
// });

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const role_name = req.role_name;
    const hash = bcrypt.hashSync(password, 8);

    const newUser = { username, password: hash, role_name };
    const createdUser = await Users.add(newUser);

    const fullUserDetails = await db("users")
      .join("roles", "users.role_id", "=", "roles.role_id")
      .select("users.user_id", "users.username", "roles.role_name")
      .where("users.user_id", createdUser.user_id)
      .first();

    res.status(201).json({
      user_id: fullUserDetails.user_id,
      username: fullUserDetails.username,
      role_name: fullUserDetails.role_name,
    });
  } catch (err) {
    next(err);
  }
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;

  Users.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        db("users")
          .join("roles", "users.role_id", "=", "roles.role_id")
          .select("users.user_id", "users.username", "roles.role_name")
          .where("users.user_id", user.user_id)
          .first()
          .then((fullUserDetails) => {
            const payload = {
              subject: fullUserDetails.user_id,
              username: fullUserDetails.username,
              role_name: fullUserDetails.role_name,
            };
            const options = { expiresIn: "1d" };
            const token = jwt.sign(payload, JWT_SECRET, options);

            res.status(200).json({
              message: `${user.username} is back!`,
              token,
            });
          })
          .catch(next);
      } else {
        next({ status: 401, message: "Invalid Credentials" });
      }
    })
    .catch(next);
});

/**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

function buildToken(user) {
  // this function creates the token
  const payload = {
    subject: user.id, // sub in payload is what the token is about
    username: user.username, // these are the user's claims
    role: user.role, // this is the user's claims
  };

  const options = {
    expiresIn: "1d", // show other available options in the library's documentation
  };

  return jwt.sign(payload, JWT_SECRET, options); // this method is synchronous, the secret string is used to decode the token
}

module.exports = router;
