var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session2 from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  consultants: () => consultants,
  insertConsultantSchema: () => insertConsultantSchema,
  insertUserSchema: () => insertUserSchema,
  users: () => users
});
import { pgTable, text, serial } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
var consultants = pgTable("consultants", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  password: text("password").notNull()
});
var insertConsultantSchema = createInsertSchema(consultants).pick({
  name: true,
  password: true
});
var users = consultants;
var insertUserSchema = insertConsultantSchema;

// server/db.ts
import pkg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
var { Pool } = pkg;
var getDatabaseUrl = () => {
  const host = "controlehoras-db.c8pqeqc0u2u5.us-east-1.rds.amazonaws.com";
  const port = "5432";
  const database = "controlehoras";
  const username = process.env.PGUSER || process.env.PGUSERNAME;
  const password = process.env.PGPASSWORD;
  if (!username || !password) {
    throw new Error(
      "Credenciais do banco de dados devem ser configuradas. Configure as vari\xE1veis PGUSER e PGPASSWORD."
    );
  }
  return `postgresql://${username}:${password}@${host}:${port}/${database}`;
};
var databaseUrl = getDatabaseUrl();
console.log("[DB] Database URL configurada:", databaseUrl.replace(/:[^:@]*@/, ":***@"));
var sslConfig = process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false;
var pool = new Pool({
  connectionString: databaseUrl,
  ssl: sslConfig
});
var db = drizzle(pool, { schema: schema_exports });

// server/storage.ts
import { eq } from "drizzle-orm";
import session from "express-session";
import connectPg from "connect-pg-simple";
var PostgresSessionStore = connectPg(session);
var DatabaseStorage = class {
  sessionStore;
  constructor() {
    this.sessionStore = new PostgresSessionStore({
      pool,
      createTableIfMissing: true,
      tableName: "session"
      // Explicitly set table name
    });
  }
  async getUser(id) {
    const [user] = await db.select().from(consultants).where(eq(consultants.id, id));
    return user || void 0;
  }
  async getUserByUsername(username) {
    console.log(`[STORAGE] Buscando usu\xE1rio: ${username}`);
    try {
      const [user] = await db.select().from(consultants).where(eq(consultants.name, username));
      console.log(`[STORAGE] Resultado da busca:`, user || "Nenhum usu\xE1rio encontrado");
      return user || void 0;
    } catch (error) {
      console.error(`[STORAGE] Erro ao buscar usu\xE1rio:`, error);
      throw error;
    }
  }
  async createUser(insertUser) {
    const [user] = await db.insert(consultants).values(insertUser).returning();
    return user;
  }
};
var storage = new DatabaseStorage();

// server/auth.ts
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  if (!stored.includes(".")) {
    return supplied === stored;
  }
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = await scryptAsync(supplied, salt, 64);
  return timingSafeEqual(hashedBuf, suppliedBuf);
}
function setupAuth(app2) {
  const sessionSettings = {
    secret: process.env.SESSION_SECRET || "your-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1e3
      // 24 hours
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session2(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(
      { usernameField: "name" },
      // Use 'name' field instead of 'username'
      async (name, password, done) => {
        try {
          console.log(`[AUTH] Tentativa de login: ${name}`);
          const user = await storage.getUserByUsername(name);
          console.log(`[AUTH] Usu\xE1rio encontrado:`, user ? "Sim" : "N\xE3o");
          if (!user) {
            console.log(`[AUTH] Usu\xE1rio n\xE3o encontrado: ${name}`);
            return done(null, false);
          }
          const passwordMatch = await comparePasswords(password, user.password);
          console.log(`[AUTH] Senha correta:`, passwordMatch ? "Sim" : "N\xE3o");
          console.log(`[AUTH] Senha fornecida: '${password}', Senha armazenada: '${user.password}'`);
          if (!passwordMatch) {
            return done(null, false);
          } else {
            console.log(`[AUTH] Login bem-sucedido para: ${name}`);
            return done(null, user);
          }
        } catch (error) {
          console.error(`[AUTH] Erro no login:`, error);
          return done(error);
        }
      }
    )
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const { name, password } = req.body;
      if (!name || !password) {
        return res.status(400).json({ message: "Nome e senha s\xE3o obrigat\xF3rios" });
      }
      const existingUser = await storage.getUserByUsername(name);
      if (existingUser) {
        return res.status(400).json({ message: "Usu\xE1rio j\xE1 existe" });
      }
      const user = await storage.createUser({
        name,
        password: await hashPassword(password)
      });
      req.login(user, (err) => {
        if (err) return next(err);
        res.status(201).json(user);
      });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
      if (err) return next(err);
      if (!user) {
        return res.status(401).json({ message: "Usu\xE1rio ou senha inv\xE1lidos" });
      }
      req.login(user, (err2) => {
        if (err2) return next(err2);
        res.status(200).json(user);
      });
    })(req, res, next);
  });
  app2.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    res.json(req.user);
  });
}

// server/routes.ts
async function registerRoutes(app2) {
  app2.get("/health", (req, res) => {
    res.status(200).json({
      status: "ok",
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      environment: process.env.NODE_ENV || "development",
      port: process.env.PORT || "5000"
    });
  });
  app2.get("/health/detailed", async (req, res) => {
    const startTime = Date.now();
    try {
      console.log("[HEALTH] Starting detailed health check...");
      const dbTest = await Promise.race([
        db.execute("SELECT 1"),
        new Promise(
          (_, reject) => setTimeout(() => reject(new Error("Database connection timeout")), 5e3)
        )
      ]);
      const duration = Date.now() - startTime;
      console.log(`[HEALTH] Database test successful in ${duration}ms`);
      res.status(200).json({
        status: "ok",
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        database: "connected",
        duration: `${duration}ms`,
        environment: process.env.NODE_ENV || "development"
      });
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`[HEALTH] Detailed health check failed in ${duration}ms:`, error);
      res.status(503).json({
        status: "error",
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        database: "disconnected",
        duration: `${duration}ms`,
        environment: process.env.NODE_ENV || "development",
        error: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  setupAuth(app2);
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen(port, "0.0.0.0", () => {
    log(`serving on port ${port}`);
  });
})();
