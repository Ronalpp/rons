import { Pool } from 'pg';

async function main() {
  try {
    // Connect to the PostgreSQL database
    const pool = new Pool({
      connectionString: 'postgresql://db_user:1234567890@176.100.37.111:5432/euwoon'
    });

    console.log('Connected to the database');

    // Create users table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('Users table created or already exists');

    // Insert sample users
    const sampleUsers = [
      {
        name: 'John Doe',
        username: 'johndoe',
        email: 'john@example.com',
        password: 'password123'
      },
      {
        name: 'Jane Smith',
        username: 'janesmith',
        email: 'jane@example.com',
        password: 'securepass456'
      },
      {
        name: 'Admin User',
        username: 'admin',
        email: 'admin@example.com',
        password: 'adminpass789'
      }
    ];

    // Insert each user, skipping if username or email already exists
    for (const user of sampleUsers) {
      try {
        await pool.query(
          `INSERT INTO users (name, username, email, password) 
           VALUES ($1, $2, $3, $4) 
           ON CONFLICT (username) DO NOTHING`,
          [user.name, user.username, user.email, user.password]
        );
        console.log(`User ${user.username} inserted or already exists`);
      } catch (error) {
        console.error(`Error inserting user ${user.username}:`, error);
      }
    }

    // Verify users were inserted
    const result = await pool.query('SELECT * FROM users');
    console.log('Users in database:', result.rows);

    // Close the connection
    await pool.end();
    console.log('Database connection closed');
  } catch (error) {
    console.error('Database operation failed:', error);
  }
}

// Execute the main function
main().catch(error => {
  console.error('Unhandled error:', error);
});
