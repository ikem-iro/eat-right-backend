# FastAPI User Registration and Authentication 🚀

This project demonstrates a basic user registration and authentication system using FastAPI, SQLModel, and SQLite. It includes features like user registration, login, and password hashing.

## 📁 Project Structure

```plaintext
├── main.py
├── user_model.py
├── user_routes.py
├── config.py
├── utils.py
└── db.py

🛠️ Setup and Installation

## Clone the repository
git clone https://github.com/yourusername/fastapi-user-authentication.git
cd fastapi-user-authentication


## Install the dependencies
pip install -r requirements.txt


## Run the application
uvicorn main:app --reload


📝 Description
main.py: Entry point for the FastAPI application.
user_model.py: Defines the user data model and validation.
user_routes.py: Defines the user registration and login routes.
config.py: Contains security configurations like secret key and token expiration.
utils.py: Contains utility functions for password hashing and authentication.
db.py: Contains database-related utilities and functions.



📚 Data Model
UserCreate
first_name: First name of the user.
last_name: Last name of the user.
email: Email address of the user.
date_of_birth: Date of birth of the user.
password: Password of the user.
confirm_password: Confirmation of the user's password.
User
Inherits from UserCreate and includes an id field.
Token
access_token: Access token for authenticated users.
token_type: Token type (default: "bearer").


🛠️ API Routes
User Registration
POST /register
Input: UserCreate data
Output: Registered user data
User Login
POST /login
Input: OAuth2PasswordRequestForm (email and password)
Output: Access token


📝 Configuration
Secret Key: Used for generating and verifying tokens.
Algorithm: Algorithm used for token generation.
Access Token Expiration: Number of minutes after which the access token will expire.


🧪 Testing
To test the API endpoints, you can use tools like Postman or curl.

🌐 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

📝 License
This project is licensed under the MIT License - see the LICENSE file for details.