import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import env from "dotenv";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import multer from "multer";
import fs from "fs";
import path from "path";
import pgSession from "connect-pg-simple";

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
env.config();


const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
    ssl: {
        require: true,
        rejectUnauthorized: false
    }
})

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
})

const upload = multer({ storage: storage })


app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}))

app.use(
    session({
        store: new pgSession({
            db: db,
            tableName: "session"
        }),
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 1000 * 60 * 60,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax"
        }
    })
);

app.use(passport.initialize());
app.use(passport.session());

function isLogged(req, res, next) {
    if(req.isAuthenticated()) {
        next();
    } else {
        res.redirect("/login");
    }
}

db.connect();


app.get("/", (req, res) => {
    res.render("home.ejs");
})

app.get("/register", (req, res) => {
    res.render("registration.ejs");
})

app.get("/login", (req, res) => {
    res.render("login.ejs");
})

app.get("/about", (req, res) => {
    res.render("about.ejs")
})

app.get("/terms", (req, res) => {
    res.render("terms.ejs")
})

app.get("/user/profile", isLogged, async (req, res) => {
        const userId = parseInt(req.user.id, 10);
        const data = `SELECT 
            users.id, 
            users.firstname, 
            users.lastname, 
            users.username, 
            users.email, 
            users_details.tel, 
            users_details.address,
            users_details.image
            FROM users LEFT JOIN users_details ON users.id = users_details.id WHERE users.id = $1`
        const result = await db.query(data, 
            [userId]
        );
        const loginDetails = result.rows[0];
        res.render("user_profile.ejs", { userDetails: loginDetails})
});

app.get("/edit/profile", isLogged, (req, res) => {
    res.render("edit_profile.ejs")
})

app.get("/create/blog", isLogged,  (req, res) => {
    res.render("create_blog.ejs", { editBlogs: null})
});

app.get("/dashboard", isLogged, async (req, res) => {
    const userId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const offset = (page - 1) * limit;

    try {
        const result = await db.query(
            "SELECT * FROM blogs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            [userId, limit, offset]
        );

        const user = await db.query(
            "SELECT username FROM users WHERE id = $1",
            [userId]
        )
            const userImage = await db.query(
                "SELECT image FROM users_details WHERE id = $1",
                [userId]
            )
            const countResult = await db.query("SELECT COUNT(*) FROM blogs WHERE user_id = $1", [userId]);
            const totalBlogs = parseInt(countResult.rows[0].count);
            const totalPages = Math.ceil(totalBlogs / limit);

        if (result.rows.length > 0) {
            res.render("dashboard.ejs", {
                userBlogs: result.rows,
                userImage: userImage.rows[0],
                user: user.rows[0],
                currentPage: page,
                totalPages,
                editBlogs: null
            });
        } else {
            res.render("dashboard.ejs", {
                msg: "No Post",
                userBlogs: result.rows,
                userImage: userImage.rows[0],
                user: user.rows[0],
                currentPage: page,
                totalPages: null,
                editBlogs: null
            })
        }
    } catch (err) {

    }
});

app.post("/register", async (req, res) => {
    const { firstname, lastname, username, email, password, terms} = req.body;
    try {
        if(!firstname || !lastname || !username || !email || !password || !terms) {
            res.render("registration.ejs", { msg: "Fill in all the fields below to continue"})
        } else {
        const checkResult = await db.query(
            "SELECT * from users WHERE email = $1",
            [email]
        );

        if (checkResult.rows.length > 0) {
            res.render("registration.ejs", {msg: "User already exists, try logging in"});
        } else if (terms)  {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log("error hashing password: " + err)
                } else {
                const result = await db.query(
                        "INSERT INTO users (firstname, lastname, username, email, password, terms) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
                        [firstname, lastname, username, email, hash,  terms]
                    );

                    const user = result.rows[0];
                    req.login(user, (err) => {
                       res.redirect("/dashboard")
                    });

                } 
            });
        } else {
           res.render("registration.ejs", {msg: "Kindly accept the terms and condition by checking the box to continue"})
        }
        }
    } catch (err) {
       console.log(err)
    }
})

app.post(
    "/login",
    passport.authenticate("local", {
        successRedirect: "dashboard",
        failureRedirect: "/login",
    })
);

app.post("/user", upload.single("image"), async (req, res) => {
    const { firstname, lastname, username, email, tel, address} = req.body;
    const image = req.file ? req.file.filename : null;
    const userId = parseInt(req.user.id, 10);

    try {

        if(!firstname && !lastname && !username && !email && !tel && !address) {

            res.render("edit_profile.ejs", { msg: "No fields inputed"})
        } else {
        
        const result = await db.query(
            "SELECT * FROM users_details WHERE id = $1",
            [userId]
        );

        if (result.rows.length > 0) {

            await db.query(
                "UPDATE users_details SET tel = COALESCE(NULLIF($1, ''), tel), address = COALESCE(NULLIF($2, ''), address), image = COALESCE(NULLIF($3, ''), image) WHERE id = $4",
                [tel, address, image, userId]
            );

            await db.query(
                "UPDATE users SET firstname = COALESCE(NULLIF($1, ''), firstname), lastname = COALESCE(NULLIF($2, ''), lastname), username = COALESCE(NULLIF($3, ''), username),  email = COALESCE(NULLIF($4, ''), email) WHERE id = $5",
                [firstname, lastname, username, email, userId]
            );
            res.render("edit_profile.ejs", { msg: "Profile Updated successfully"})

        } else {
            await db.query(
                "INSERT INTO users_details (id, tel, address, image) VALUES ($1, $2, $3, $4)",
                [userId, tel, address, image]
            );

            res.render("edit_profile.ejs", { msg: "Profile Saved successfully"})
        }

    }


    } catch (err) {

        console.log(err)

    }
});


app.post("/user/blog", upload.single("image"), async (req, res) => {
    const userId = parseInt(req.user.id, 10);
    const { title, content } = req.body;
    const image = req.file? req.file.filename : null;

    try {
            if (image) {
            await db.query(
                "INSERT INTO blogs (user_id, title, content, image) VALUES ($1, $2, $3, $4)",
                [userId, title, content, image]
            );
        } else {

            await db.query(
                "INSERT INTO blogs (user_id, title, content) VALUES ($1, $2, $3)",
                [userId, title, content]
            );

        }

            res.render("create_blog.ejs", { 
                editBlogs: null,
                msg: "Blog Posted Successfully"
            })

    } catch (err) {
       console.log(err)
    }
  
});

app.post("/user/blog/delete/", async (req, res) => {
    const userId = req.user.id;
    const blogId = req.body.id;
    const page = req.query.page || 1;
    try {
         const result = await db.query("SELECT image FROM blogs WHERE id = $1", [blogId])
         const image = result.rows[0]?.image;

        await db.query("DELETE FROM blogs WHERE id = $1 AND user_id = $2",
            [blogId, userId]
        );

        if (image) {
      const imagePath = path.join("public", "uploads", image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    res.redirect(`/dashboard?page=${page}`)

    } catch (err) {
      console.log(err)
    }
})

app.post("/user/blog/update", upload.single("image"), async (req, res) => {
    const { title, content } = req.body;
    const userId = req.user.id;
    const image = req.file? req.file.filename : null;
    try {

        const result = await db.query(
            "SELECT * FROM blogs WHERE user_id = $1",
            [userId]
        );
            const user = result.rows[0];

            if (image) {


            await db.query(
                "UPDATE blogs SET title = $1, image = $2, content = $3 WHERE id = $4",
                [title, image, content, user.id]
            );

        } else {
            await db.query(
               "UPDATE blogs SET title = $1, content = $2 WHERE id = $3",
               [title, content, user.id]
            );
        }

        res.render("create_database.ejs", { editBlogs: null});

    } catch (err) {

    }
})

app.get("/user/blog/edit", isLogged, async (req, res) => {

    const userId = req.user.id;

    try {

        const result = await db.query(
            "SELECT * FROM blogs WHERE user_id = $1",
            [userId]
        );

        const user = result.rows[0];
        console.log(user)

        res.render("create_database.ejs", { editBlogs: user })
    } catch (err) {

    }
})

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
          return next(err)
        } else {
            res.redirect("/")
        }
    })
})


passport.use(
    new Strategy(async function verify (username, password, cb) {

        try {

            const result = await db.query(
                "SELECT * FROM users WHERE username = $1",
                [username]
            );

            if(result.rows.length > 0) {
                const user = result.rows[0];
                const storedPassword = user.password;

                bcrypt.compare(password, storedPassword, (err, result) => {
                   
                    if (err) {
                        console.error(err)
                        return cb(err)
                    } else if (result) {
                        return cb(null, user)
                    } else {
                        return cb("Incorrect Password", false)
                    }
                })
            } else {
                return cb("User not found")
                }

        } catch (err) {
            console.log(err)
        }
        
    })
);

passport.serializeUser((user, cb) => {
    cb(null, user)
})

passport.deserializeUser((user, cb) => {
    cb(null, user)
})
    

app.listen(port, ()=> {
    console.log(`Server is running successfully on port ${port}`)
});