import express from 'express';
import cors from 'cors';
import { config } from 'dotenv';
import pg from 'pg';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { AuthenticatedRequest, ApiError } from './types.js';

config();

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const pool = new pg.Pool({
  host: process.env.POSTGRES_HOST,
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASSWORD,
  database: process.env.POSTGRES_DB,
  port: parseInt(process.env.POSTGRES_PORT || '5432'),
});

// Middleware
app.use(cors());
app.use(express.json());

// Error handler middleware
const errorHandler = (err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  const apiError: ApiError = {
    message: err.message || 'Internal server error',
    code: 'INTERNAL_ERROR'
  };
  res.status(500).json(apiError);
};

// Auth middleware
const authenticateToken = (req: AuthenticatedRequest, res: express.Response, next: express.NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required', code: 'AUTH_REQUIRED' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token', code: 'INVALID_TOKEN' });
    }
    req.user = user;
    next();
  });
};

// Schema validation
const registerSchema = z.object({
  name: z.string().min(2).max(255),
  username: z.string().min(3).max(255).regex(/^[a-zA-Z0-9_]+$/),
  email: z.string().email(),
  password: z.string().min(6),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

const createDbSchema = z.object({
  name: z.string().min(1).max(63).regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/),
  username: z.string().min(3).max(63).regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/),
  password: z.string().min(6).max(255),
});

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, username, email, password } = registerSchema.parse(req.body);

    // Check if user exists
    const userExists = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).json({
        message: 'Usuario o correo electrónico ya existe',
        code: 'USER_EXISTS'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(
      'INSERT INTO users (name, username, email, password) VALUES ($1, $2, $3, $4) RETURNING id, name, username, email',
      [name, username, email, hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign(user, JWT_SECRET);

    res.status(201).json({ user, token });
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      res.status(400).json({
        message: 'Datos de registro inválidos',
        code: 'VALIDATION_ERROR',
        details: error.errors
      });
    } else {
      res.status(500).json({
        message: 'Error en el registro',
        code: 'REGISTRATION_ERROR'
      });
    }
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: 'Credenciales inválidas',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email
      },
      JWT_SECRET
    );

    res.json({
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({
        message: 'Datos de inicio de sesión inválidos',
        code: 'VALIDATION_ERROR',
        details: error.errors
      });
    } else {
      res.status(500).json({
        message: 'Error en el inicio de sesión',
        code: 'LOGIN_ERROR'
      });
    }
  }
});

app.get('/api/auth/me', authenticateToken, (req: AuthenticatedRequest, res) => {
  res.json(req.user);
});

// Database routes
app.post(
  '/api/databases',
  authenticateToken,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { name, username, password } = createDbSchema.parse(req.body);

      // Create new database
      await pool.query(`CREATE DATABASE ${name}`);

      // Create database user with password
      await pool.query(`CREATE USER ${username} WITH PASSWORD '${password}'`);
      
      // Grant privileges to the new user
      await pool.query(`GRANT ALL PRIVILEGES ON DATABASE ${name} TO ${username}`);

      // Generate connection string
      const connectionString = `postgresql://${username}:${password}@${process.env.POSTGRES_HOST}:${process.env.POSTGRES_PORT}/${name}`;

      // Record the database creation
      await pool.query(
        'INSERT INTO user_databases (name, owner_id, username, password, connection_string) VALUES ($1, $2, $3, $4, $5)',
        [name, req.user?.id, username, password, connectionString]
      );

      res.status(201).json({ 
        message: 'Base de datos creada exitosamente',
        connectionString
      });
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          message: 'Datos inválidos',
          code: 'VALIDATION_ERROR',
          details: error.errors
        });
      } else {
        res.status(500).json({
          message: 'Error al crear la base de datos',
          code: 'DATABASE_ERROR',
          details: error.message
        });
      }
    }
  }
);

app.get(
  '/api/databases',
  authenticateToken,
  async (req: AuthenticatedRequest, res) => {
    try {
      const result = await pool.query(
        'SELECT id, name, username, connection_string, created_at FROM user_databases WHERE owner_id = $1',
        [req.user?.id]
      );

      res.json(result.rows);
    } catch (error) {
      res.status(500).json({
        message: 'Error al obtener las bases de datos',
        code: 'DATABASE_ERROR'
      });
    }
  }
);

app.get(
  '/api/databases/:name',
  authenticateToken,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { name } = req.params;

      // Verify ownership
      const dbCheck = await pool.query(
        'SELECT * FROM user_databases WHERE name = $1 AND owner_id = $2',
        [name, req.user?.id]
      );

      if (dbCheck.rows.length === 0) {
        return res.status(403).json({
          message: 'No tienes permiso para acceder a esta base de datos',
          code: 'UNAUTHORIZED'
        });
      }

      // Get database details
      const dbConn = new pg.Pool({
        host: process.env.POSTGRES_HOST,
        user: dbCheck.rows[0].username,
        password: dbCheck.rows[0].password,
        database: name,
        port: parseInt(process.env.POSTGRES_PORT || '5432'),
      });

      // Get tables
      const tablesResult = await dbConn.query(`
        SELECT table_name, column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
        ORDER BY table_name, ordinal_position
      `);

      await dbConn.end();

      // Organize tables and columns
      const tables = tablesResult.rows.reduce((acc: any, row: any) => {
        if (!acc[row.table_name]) {
          acc[row.table_name] = {
            name: row.table_name,
            columns: []
          };
        }
        acc[row.table_name].columns.push({
          name: row.column_name,
          type: row.data_type
        });
        return acc;
      }, {});

      res.json({
        name,
        tables: Object.values(tables),
        username: dbCheck.rows[0].username,
        connection_string: dbCheck.rows[0].connection_string,
        created_at: dbCheck.rows[0].created_at
      });
    } catch (error) {
      res.status(500).json({
        message: 'Error al obtener los detalles de la base de datos',
        code: 'DATABASE_ERROR'
      });
    }
  }
);

app.post(
  '/api/databases/:name/query',
  authenticateToken,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { name } = req.params;
      const { query } = req.body;

      if (!query) {
        return res.status(400).json({
          message: 'La consulta es requerida',
          code: 'VALIDATION_ERROR'
        });
      }

      // Verify ownership and get credentials
      const dbCheck = await pool.query(
        'SELECT * FROM user_databases WHERE name = $1 AND owner_id = $2',
        [name, req.user?.id]
      );

      if (dbCheck.rows.length === 0) {
        return res.status(403).json({
          message: 'No tienes permiso para acceder a esta base de datos',
          code: 'UNAUTHORIZED'
        });
      }

      // Execute query using database-specific credentials
      const dbConn = new pg.Pool({
        host: process.env.POSTGRES_HOST,
        user: dbCheck.rows[0].username,
        password: dbCheck.rows[0].password,
        database: name,
        port: parseInt(process.env.POSTGRES_PORT || '5432'),
      });

      const result = await dbConn.query(query);
      await dbConn.end();

      res.json({
        rows: result.rows,
        rowCount: result.rowCount,
        fields: result.fields.map((f: any) => ({
          name: f.name,
          dataType: f.dataTypeID
        }))
      });
    } catch (error: any) {
      res.status(400).json({
        message: 'Error al ejecutar la consulta',
        code: 'QUERY_ERROR',
        details: error.message
      });
    }
  }
);

app.delete(
  '/api/databases/:name',
  authenticateToken,
  async (req: AuthenticatedRequest, res) => {
    try {
      const { name } = req.params;

      // Verify ownership and get credentials
      const dbCheck = await pool.query(
        'SELECT * FROM user_databases WHERE name = $1 AND owner_id = $2',
        [name, req.user?.id]
      );

      if (dbCheck.rows.length === 0) {
        return res.status(403).json({
          message: 'No tienes permiso para eliminar esta base de datos',
          code: 'UNAUTHORIZED'
        });
      }

      // Drop database
      await pool.query(`DROP DATABASE IF EXISTS ${name}`);
      
      // Drop user
      await pool.query(`DROP USER IF EXISTS ${dbCheck.rows[0].username}`);

      // Remove record
      await pool.query('DELETE FROM user_databases WHERE name = $1', [name]);

      res.json({ message: 'Base de datos eliminada exitosamente' });
    } catch (error) {
      res.status(500).json({
        message: 'Error al eliminar la base de datos',
        code: 'DATABASE_ERROR'
      });
    }
  }
);

// Error handling middleware
app.use(errorHandler);

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  
  // Listen for keypress events
  process.stdin.resume();
  process.stdin.on('data', (key) => {
    // Check if 'i' key is pressed
    if (key.toString() === 'i') {
      console.log('Initializing database...');
      try {
        // Execute init-db.ts
        require('./init-db');
        console.log('Database initialization triggered');
      } catch (error) {
        console.error('Error initializing database:', error);
      }
    }
    
    // Allow Ctrl+C to exit
    if (key.toString() === '\u0003') {
      process.exit();
    }
  });
});