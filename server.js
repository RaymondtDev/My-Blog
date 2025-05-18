const express = require("express");
const db = require("better-sqlite3")("blog.db");
const JWT = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sanitizeHTML = require("sanitize-html");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const marked = require("marked");
const dotenv = require("dotenv");

// Enable WAL mode for better concurrency and performance
db.pragma("journal_mode = WAL");

// create a tanle for blog posts if it does not exist
const createTables = db.transaction(() => {
  db.prepare(
    `CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      likes INTEGER DEFAULT 0,
      author_id INTEGER,
      FOREIGN KEY (author_id) REFERENCES admins(id)
    )`
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )`
  ).run();
});
createTables();

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use('/assets', express.static('assets'));
app.use(cookieParser());

app.use(function (req, res, next) {
  res.locals.errors = [];

  try {
    const decoded = JWT.verify(req.cookies.token, process.env.JWT_SECRET);
    res.admin = decoded;
  } catch (error) {
    res.admin = false;
  }

  res.locals.admin = res.admin;
  next();
});

const isLoggedIn = (req, res, next) => {
  // if not logged in, redirect to login page
  if (!res.admin) {
    return res.redirect("/login");
  }
  next();
};

app.get("/", (req, res) => {
  // get all posts from database
  const posts = db
    .prepare("SELECT * FROM posts ORDER BY created_at DESC")
    .all();
  res.render("homepage", { posts, admin: res.admin });
});

// get post by id
app.get("/posts/:id", (req, res) => {
  const postId = req.params.id;
  const post = db.prepare(`
    SELECT posts.*, admins.username AS author_username
    FROM posts
    LEFT JOIN admins ON posts.author_id = admins.id
    WHERE posts.id = ?
  `).get(postId);
  if (!post) {
    return res.status(404).send("Post not found");
  }
  const renderedContent = marked.parse(post.content);
  res.render("post", { renderedContent, post, admin: res.admin });
});

// get admin page
app.get("/admin", isLoggedIn, (req, res) => {
  // get all posts by admin
  const posts = db
    .prepare("SELECT * FROM posts WHERE author_id = ? ORDER BY created_at DESC")
    .all(res.admin.id);
  
  res.render("admin", { admin: res.admin, posts });
});

// get login page
app.get("/login", (req, res) => {
  res.render("login");
});

// get register page
app.get("/register", (req, res) => {
  res.render("register");
});

// get create post page
app.get("/admin/posts/new", isLoggedIn, (req, res) => {
  res.render("create-post", { admin: res.admin });
});

// get edit post
app.get("/admin/posts/:id/edit", isLoggedIn, (req, res) => {
  const postId = req.params.id;
  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(postId);
  if (!post) {
    return res.status(404).send("Post not found");
  }
  res.render("edit-post", { post, admin: res.admin });
});

//create admin user
app.post("/register", (req, res) => {
  const errors = [];
  let { username, email, password } = req.body;

  // check if username, email and password are not empty
  if (typeof username !== "string") username = "";
  if (typeof email !== "string") email = "";
  if (typeof password !== "string") password = "";

  username = username.trim();
  email = email.trim();

  if (!username) errors.push("Username cannot be empty.");
  if (username && username.length < 3)
    errors.push("Username must be at least 3 characters long");
  if (username && username.length > 10)
    errors.push("Username must not exceed 10 characters.");
  if (username && !username.match(/^[a-zA-Z0-9]+$/))
    errors.push('Username cannot have special characters "!@#$%^&*"');

  if (!email) errors.push("Email cannot be empty.");
  if (email && email.length < 15)
    errors.push("Email must be at least 15 characters long");
  if (email && email.length > 50)
    errors.push("Email must not exceed 50 characters.");

  if (!password) errors.push("Passoword cannot be empty.");
  if (password && password.length < 12)
    errors.push("Password must be at least 12 characters long");
  if (password && password.length > 70)
    errors.push("Password must not exceed 70 characters.");

  // check if email is already in use
  const emailExists = db
    .prepare("SELECT * FROM admins WHERE email = ?")
    .get(email);
  if (emailExists) {
    errors.push("Email already in use");
  }

  if (errors.length) {
    return res.render("register", { errors });
  }

  // hash password
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);
  // insert new admin into database
  const newAdmin = db
    .prepare("INSERT INTO admins (username, email, password) VALUES (?, ?, ?)")
    .run(username, email, hashedPassword);

  const adminUser = db
    .prepare("SELECT * FROM admins WHERE ROWID = ?")
    .get(newAdmin.lastInsertRowid);
  // create a JWT token
  const token = JWT.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      id: adminUser.id,
      username: adminUser.username,
    },
    process.env.JWT_SECRET
  );

  // store the token in the session
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  res.redirect("/login");
});

// create a new post
app.post("/admin/create-post", isLoggedIn, (req, res) => {
  const errors = [];

  let { title, content } = req.body;

  // check if title and content are not empty
  if (typeof title !== "string") title = "";
  if (typeof content !== "string") content = "";

  title = sanitizeHTML(title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });
  content = sanitizeHTML(content.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!title) errors.push("Title cannot be empty.");
  if (title && title.length < 5)
    errors.push("Title must be at least 5 characters long");
  if (title && title.length > 50)
    errors.push("Title must not exceed 50 characters.");

  if (!content) errors.push("Content cannot be empty.");

  if (errors.length) {
    return res.render("create-post", { errors });
  }

  // insert new post into database
  db.prepare(
    "INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)"
  ).run(title, content, res.admin.id);

  res.redirect("/admin");
});

// update a post
app.post("/admin/posts/:id", isLoggedIn, (req, res) => {
  const errors = [];
  let { title, content } = req.body;
  const postId = req.params.id;

  // check if title and content are not empty
  if (typeof title !== "string") title = "";
  if (typeof content !== "string") content = "";

  title = title.trim();
  content = content.trim();

  if (!title) errors.push("Title cannot be empty.");
  if (title && title.length < 5)
    errors.push("Title must be at least 5 characters long");
  if (title && title.length > 50)
    errors.push("Title must not exceed 50 characters.");

  if (!content) errors.push("Content cannot be empty.");
  if (content && content.length < 20)
    errors.push("Content must be at least 20 characters long");
  if (content && content.length > 5000)
    errors.push("Content must not exceed 5000 characters.");

  if (errors.length) {
    return res.render("edit-post", { errors });
  }

  // update post in database
  db.prepare(
    "UPDATE posts SET title = ?, content = ? WHERE id = ?"
  ).run(title, content, postId);

  res.redirect("/");
});

// delete post
app.post("/admin/posts/:id/delete", isLoggedIn, (req, res) => {
  const postId = req.params.id;

  // delete post from database
  db.prepare("DELETE FROM posts WHERE id = ?").run(postId);

  res.redirect("/admin");
});

// like post
app.post("/posts/:id/like", (req, res) => {
  const postId = req.params.id;

  // check if user is logged in
  if (!res.admin) {
    return res.status(401).send("Unauthorized");
  }

  // check if post exists
  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(postId);
  if (!post) {
    return res.status(404).send("Post not found");
  }

  // increment likes count
  db.prepare("UPDATE posts SET likes = likes + 1 WHERE id = ?").run(postId);

  res.redirect("/");
});

// login
app.post("/login", (req, res) => {
  const errors = [];
  // TODO: create login logic
  // if login successful, redirect to admin page

  const { email, password } = req.body;

  if (!email) errors.push("Email cannot be empty.");
  if (email && email.length < 15)
    errors.push("Email must be at least 15 characters long");
  if (email && email.length > 50)
    errors.push("Email must not exceed 50 characters.");

  if (!password) errors.push("Passoword cannot be empty.");

  if (errors.length) {
    return res.render("login", { errors });
  }

  const admin = db.prepare("SELECT * FROM admins WHERE email = ?").get(email);

  if (!admin) {
    errors.push("Invalid email or password");
    return res.render("login", { errors });
  }

  const isMatch = bcrypt.compareSync(password, admin.password);
  // check if password is correct
  if (!isMatch) {
    errors.push("Invalid email or password");
    return res.render("login", { errors });
  }

  // create a JWT token
  const token = JWT.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      id: admin.id,
      username: admin.username,
    },
    process.env.JWT_SECRET
  );

  // store the token in the session
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    maxAge: 1000 * 60 * 60 * 24,
  });

  // redirect to admin page
  res.redirect("/admin");
});

// logout
app.get("/logout", (req, res) => {
  // destroy the session
  res.clearCookie("token");
  res.redirect("/");
});

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
