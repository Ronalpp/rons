import { Request } from 'express';

export interface Database {
  id: string;
  name: string;
  owner_id: string;
  username: string;
  password: string;
  connection_string: string;
  created_at: Date;
}

export interface User {
  id: string;
  name: string;
  username: string;
  email: string;
  password: string;
  created_at: Date;
}

export interface DatabaseUser {
  username: string;
  password: string;
  permissions: string[];
}

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    name: string;
    username: string;
    email: string;
  };
}

export interface ApiError {
  message: string;
  code: string;
  details?: any;
}