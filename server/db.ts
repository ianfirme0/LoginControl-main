import pkg from 'pg';
const { Pool } = pkg;
import { drizzle } from 'drizzle-orm/node-postgres';
import * as schema from "@shared/schemaconst getDatabaseUrl = () => {
  // In production (Railway), DATABASE_URL is required.
  if (process.env.NODE_ENV === 'production') {
    if (!process.env.DATABASE_URL) {
      throw new Error(
        "A variável de ambiente DATABASE_URL não está configurada. Adicione um serviço de banco de dados no Railway e vincule-o a este serviço."
      );
    }
    return process.env.DATABASE_URL;
  }

  // For local development, fallback to AWS RDS connection details
  const host = 'controlehoras-db.c8pqeqc0u2u5.us-east-1.rds.amazonaws.com';
  const port = '5432';
  const database = 'controlehoras';
  const username = process.env.PGUSER || process.env.PGUSERNAME;
  const password = process.env.PGPASSWORD;
  
  if (!username || !password) {
    throw new Error(
      "Para desenvolvimento local, configure as variáveis de ambiente PGUSER e PGPASSWORD."
    );
  }
  
  return `postgresql://${username}:${password}@${host}:${port}/${database}`;
};

const databaseUrl = getDatabaseUrl();
console.log('[DB] Database URL configurada:', databaseUrl.replace(/:[^:@]*@/, ':***@'));

const sslConfig = process.env.NODE_ENV === 'production' 
  ? { rejectUnauthorized: false }
  : false;

export const pool = new Pool({ 
  connectionString: databaseUrl,
  ssl: sslConfig
});
export const db = drizzle(pool, { schema });
