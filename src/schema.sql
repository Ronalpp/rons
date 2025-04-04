-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create user_databases table with username and password
CREATE TABLE IF NOT EXISTS user_databases (
    id SERIAL PRIMARY KEY,
    name VARCHAR(63) UNIQUE NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    username VARCHAR(63) NOT NULL,
    password VARCHAR(255) NOT NULL,
    connection_string TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);