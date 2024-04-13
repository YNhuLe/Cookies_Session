## 🍪 Cookies & Session 🍪

Welcome to the Cookies & Session project! This delightful project uses 🌟Express.js🌟, 🛠️ PostgreSQL, 🔐 bcrypt, and 🛡️ Passport.js to create a secure and fun user authentication system.

* 📦 Node.js
* 💻 npm (Node Package Manager)

### Installation
#### 1. Clone the repository
```bash
git clone https://github.com/YNhuLe/Cookies_Session.git
```

#### 2. Install dependencies

```bash
npm install
```

### Running the Project
#### 1. Make sure you have PostgreSQL running on your machine.
#### 2. Create a .env file in the root directory with the following variables:
```bash TOP_SECRET=YourTopSecretKey
TOP_USER=YourDatabaseUser
TOP_HOST=YourDatabaseHost
TOP_DATABASE=YourDatabaseName
TOP_PASSWORD=YourDatabasePassword
TOP_PORT=YourDatabasePort
GOOGLE_CLIENT_ID=YourGoogleClientID
GOOGLE_CLIENT_SECRET=YourGoogleClientSecret
```
#### 3. Run the project
```bash
npm start
```
#### 4. Open your browser and navigate to http://localhost:3000 to see the magic

### Features
* 🛋️ User authentication with local strategy (username and password).
* 🌐 User authentication with Google OAuth.
* 🍪 Cookies and Sessions to keep users logged in.
* 🔐 Password hashing with bcrypt.
* 🛡️ Protection against CSRF attacks.
* 📝 User data stored in a PostgreSQL database.

### Contributing
We welcome contributions! Feel free to fork this repository and submit pull requests with your enhancements. Let's make this project even more delicious together! 🍰

### Keep Calm and Code On!
Remember, coding is like baking cookies - sometimes you get a few crumbs, but it's all part of the fun! Enjoy coding and keep those creative juices flowing! 🍪✨

### Developer
* [YNhuLe]