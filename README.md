<div align="center">

<a href="https://nodejs.org/en" target="_blank"><img src="https://user-images.githubusercontent.com/3438503/260495760-ca5d8c24-b382-43d9-8fbe-d905b4b208f0.png" width="260" alt="Logo de Node.js" /></a>

# Clase 9 de Node.js

### Kopius · The Academy · Cohort 05 · M3

**API REST: Autenticación y Autorización de usuarios via JSON Web Tokens (JWT)**

![Node.js](https://img.shields.io/badge/Node.js-26.x_LTS-5FA04E?style=for-the-badge&logo=nodedotjs&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-ES_Modules-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![JWT](https://img.shields.io/badge/JWT-HS256-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![OpenAPI](https://img.shields.io/badge/Swagger-OpenAPI_3.0-85EA2D?style=for-the-badge&logo=swagger&logoColor=black)

</div>

---

> [!NOTE]
> En esta clase continuamos evolucionando la **Hospital REST API** construida en la Clase 8. Incorporamos autenticación sin estado (_stateless_) con **JSON Web Tokens (JWT)**, control de acceso basado en roles mediante middlewares, consulta del perfil autenticado, endurecimiento de seguridad alineado con **OWASP API Security Top 10** y documentación interactiva de endpoints protegidos en **Swagger / OpenAPI**.

## Mapa de planificación de la clase

| Bloque                     | Objetivo pedagógico                                                                               | Entregable en el proyecto                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| **1. Tokens**              | Comprender por qué las APIs REST modernas adoptan tokens _stateless_ frente a sesiones en memoria | Modelo conceptual de identidad y permisos                 |
| **2. Login y contraseñas** | Almacenar credenciales con _hashing_ adaptativo y validar credenciales de forma segura            | Endpoint `POST /api/auth/login`                           |
| **3. Anatomía de JWT**     | Firmar tokens, diseñar _claims_ mínimos e inspeccionar tokens en `jwt.io`                         | Utilidad `issueAccessToken` + variables de entorno        |
| **4. Protección de rutas** | Interceptar peticiones, validar firma/expiración y restringir acciones por rol                    | Middlewares `authenticate` y `authorize`                  |
| **5. Usuario autenticado** | Recuperar el perfil vigente a partir de la identidad verificada del token                         | Endpoint `GET /api/auth/me`                               |
| **6. Seguridad OWASP**     | Mitigar los riesgos más frecuentes en APIs REST (BOLA, BOPLA, BFLA, fuerza bruta)                 | Validaciones, DTOs seguros y políticas HTTP               |
| **7. Tarea 015 + Desafío** | Proteger **Hospital API**, habilitar `Bearer` en Swagger e introducir **Refresh Tokens**          | API protegida + OpenAPI actualizado + flujo de renovación |

---

## CONTENIDO

1. [Introducción a los tokens](#1-introducción-a-los-tokens)
2. [Login y contraseñas](#2-login-y-contraseñas)
3. [JWT: generación, estructura e inspección](#3-jwt-generación-estructura-e-inspección)
4. [Protección de rutas con token y middlewares](#4-protección-de-rutas-con-token-y-middlewares)
5. [Obtener información del usuario autenticado](#5-obtener-información-del-usuario-autenticado)
6. [Seguridad basada en OWASP Top 10 para REST Security](#6-seguridad-basada-en-owasp-top-10-para-rest-security)
7. [Tarea 015: Autenticación y autorización en Hospital API](#7-tarea-015-autenticación-y-autorización-en-hospital-api)
8. [Referencias](#8-referencias)

---

## 1. Introducción a los tokens

Antes de escribir código de seguridad conviene separar tres responsabilidades distintas dentro de una API REST:

| Concepto            | Pregunta que responde                               | Ejemplo en Hospital API                             |
| ------------------- | --------------------------------------------------- | --------------------------------------------------- |
| **Autenticación**   | ¿Quién realiza la petición?                         | Validar `email` y `password` en `/api/auth/login`   |
| **Autorización**    | ¿Qué tiene permitido hacer esa identidad?           | Permitir que solo `ADMIN` elimine registros médicos |
| **Token de acceso** | ¿Cómo demuestra su identidad en cada petición HTTP? | Enviar `Authorization: Bearer <token>` firmado      |

### ¿Qué problemas resolvieron los tokens?

En arquitecturas web clásicas basadas en **sesiones de servidor (_stateful_)**, el servidor crea una sesión en memoria o base de datos al iniciar sesión y entrega un `sessionId` mediante una cookie. A medida que las aplicaciones evolucionaron hacia APIs consumidas por múltiples clientes y desplegadas en múltiples instancias, aparecieron limitaciones claras:

| Problema con sesiones tradicionales                                                                                                                                                                                                | Cómo lo resuelven los tokens (_stateless_)                                                                                                                          |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Estado acoplado a la memoria del servidor:** si una API escala horizontalmente a varias instancias detrás de un balanceador, otra instancia no conoce la sesión local sin infraestructura adicional (Redis o _sticky sessions_). | El token contiene los datos de identidad firmados criptográficamente; cualquier instancia con la clave de verificación valida el token sin consultar memoria local. |
| **Clientes heterogéneos (Web SPA, Mobile, CLI, servicios B2B):** las cookies dependen del modelo de navegador y políticas de dominio.                                                                                              | El estándar `Authorization: Bearer <token>` funciona de manera uniforme en navegadores, apps móviles nativas e integraciones servidor a servidor.                   |
| **Dominios cruzados (CORS y microservicios):** compartir cookies entre dominios distintos exige configuraciones delicadas de `SameSite` y exposición a CSRF.                                                                       | El cliente adjunta explícitamente la cabecera HTTP hacia la API autorizada, simplificando el consumo entre dominios independientes.                                 |
| **Acoplamiento entre autenticación y negocio:** cada servicio debía consultar el almacén central de sesiones en cada lectura.                                                                                                      | Un servicio emisor firma el token y los demás servicios verifican la firma de forma autónoma.                                                                       |

> [!IMPORTANT]
> **Compromiso de diseño (_tradeoff_):** como un token _stateless_ es válido mientras su firma sea correcta y no haya expirado, no se invalida automáticamente en todos los clientes al cambiar permisos si tiene una vida larga. Por eso los **Access Tokens** deben tener tiempos de expiración breves (por ejemplo, `15m`).

<sub>[⬆ Volver al índice](#contenido)</sub>

---

## 2. Login y contraseñas

### Instalación de dependencias

```bash
npm install jsonwebtoken bcrypt
```

### Almacenamiento seguro de contraseñas

Las contraseñas **jamás** se guardan en texto plano ni con funciones de resumen rápidas (`MD5`, `SHA-1`, `SHA-256`). Se utiliza un algoritmo de _hashing_ adaptativo para contraseñas como **bcrypt** (o **Argon2id**), que incorpora una _sal_ aleatoria única por usuario y un factor de costo configurable:

```javascript
import bcrypt from "bcrypt";

const SALT_ROUNDS = 12;

export const hashPassword = async (plainPassword) => {
  return bcrypt.hash(plainPassword, SALT_ROUNDS);
};

export const verifyPassword = async (plainPassword, passwordHash) => {
  return bcrypt.compare(plainPassword, passwordHash);
};
```

### Creación de la ruta `POST /api/auth/login`

```mermaid
sequenceDiagram
    participant C as Cliente
    participant API as POST /api/auth/login
    participant DB as Base de Datos

    C->>API: { email, password }
    API->>DB: Buscar usuario por email
    DB-->>API: Usuario (con passwordHash y role)
    API->>API: bcrypt.compare(password, passwordHash)
    alt Credenciales válidas
        API->>API: Firmar Access Token (JWT)
        API-->>C: 200 OK { accessToken, tokenType: "Bearer", expiresIn }
    else Email inexistente o contraseña incorrecta
        API-->>C: 401 Unauthorized { error: INVALID_CREDENTIALS }
    end
```

Ejemplo de controlador y ruta de autenticación:

```javascript
// src/controllers/auth.controller.js
import { verifyPassword } from "../utils/password.js";
import { issueAccessToken } from "../utils/jwt.js";
import { UserRepository } from "../repositories/user.repository.js";

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await UserRepository.findByEmailWithPassword(email);
    const isValid = user
      ? await verifyPassword(password, user.passwordHash)
      : false;

    if (!isValid) {
      return res.status(401).json({
        error: {
          code: "INVALID_CREDENTIALS",
          message: "Invalid email or password",
        },
      });
    }

    const accessToken = issueAccessToken(user);

    return res.status(200).json({
      accessToken,
      tokenType: "Bearer",
      expiresIn: 900,
    });
  } catch (error) {
    next(error);
  }
};
```

```javascript
// src/routes/auth.routes.js
import { Router } from "express";
import { login, getAuthenticatedUser } from "../controllers/auth.controller.js";
import { authenticate } from "../middlewares/auth.middleware.js";

const authRouter = Router();

authRouter.post("/login", login);
authRouter.get("/me", authenticate, getAuthenticatedUser);

export default authRouter;
```

```javascript
// Registro en src/app.js
app.use("/api/auth", authRouter);
```

> [!TIP]
> **Prevención de enumeración de cuentas:** ante un correo inexistente o una contraseña errónea, el endpoint debe devolver exactamente el mismo código `401` y el mismo mensaje genérico (`Invalid email or password`), sin revelar cuál de los dos datos falló.

<sub>[⬆ Volver al índice](#contenido)</sub>

---

## 3. JWT: generación, estructura e inspección

Un **JSON Web Token (JWT)** definido en el estándar [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) es una cadena compacta compuesta por **tres segmentos codificados en Base64URL** y separados por puntos:

```text
xxxxx.yyyyy.zzzzz
Header.Payload.Signature
```

| Segmento      | Contenido                                                          | Propósito                                                                       |
| ------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| **Header**    | `{ "alg": "HS256", "typ": "JWT" }`                                 | Declara el algoritmo criptográfico de firma y el tipo de token                  |
| **Payload**   | `{ "sub": "42", "role": "DOCTOR", "iss": "hospital-api", ... }`    | Transporta las declaraciones (_claims_) sobre la identidad y metadatos          |
| **Signature** | `HMACSHA256(base64Url(header) + "." + base64Url(payload), secret)` | Garantiza integridad y autenticidad: detecta cualquier alteración del contenido |

### Explicación de campos (_Claims_)

| Claim                     | Tipo          | Significado y uso recomendado                                                     |
| ------------------------- | ------------- | --------------------------------------------------------------------------------- |
| `sub` (_Subject_)         | Estándar      | Identificador único e inmutable del usuario (por ejemplo, `"42"` o UUID)          |
| `iss` (_Issuer_)          | Estándar      | Sistema que emitió el token (`"hospital-api"`)                                    |
| `aud` (_Audience_)        | Estándar      | Destinatario previsto del token (`"hospital-clients"`)                            |
| `iat` (_Issued At_)       | Estándar      | Marca temporal Unix (segundos) en que fue emitido                                 |
| `exp` (_Expiration Time_) | Estándar      | Marca temporal Unix tras la cual el token debe ser rechazado                      |
| `role`                    | Personalizado | Rol de negocio (`"ADMIN"`, `"DOCTOR"`, `"RECEPTIONIST"`) para autorización rápida |

### Generación de JWT en Node.js

```javascript
// src/utils/jwt.js
import jwt from "jsonwebtoken";

export const issueAccessToken = (user) => {
  return jwt.sign(
    {
      sub: String(user.id),
      role: user.role,
    },
    process.env.JWT_SECRET,
    {
      algorithm: "HS256",
      issuer: "hospital-api",
      audience: "hospital-clients",
      expiresIn: "15m",
    },
  );
};
```

> [!WARNING]
> `JWT_SECRET` debe ser una cadena aleatoria de alta entropía (mínimo 32 bytes / 256 bits para `HS256`), definida únicamente en variables de entorno y distinta para desarrollo, pruebas y producción. Nunca debe subirse al repositorio.

### Inspección desde `jwt.io`: decodificar vs. desencriptar

> [!IMPORTANT]
> **Aclaración conceptual crítica:** suele hablarse coloquialmente de _"desencriptar un JWT"_, pero un JWT firmado estándar (**JWS**) **no está cifrado: solo está codificado en Base64URL y firmado**. Cualquier persona o script que intercepte el token puede leer su `Header` y su `Payload` sin conocer el `JWT_SECRET`. Nunca incluyas contraseñas, historias clínicas, documentos sensibles ni secretos dentro del payload.

#### Ejemplo práctico en [jwt.io](https://jwt.io)

1. Ejecuta `POST /api/auth/login` y copia el valor de `accessToken` recibido.
2. Abre [https://jwt.io](https://jwt.io) y pega el token en el panel **Encoded**.
3. Observa en el panel **Decoded** cómo se visualizan inmediatamente el **HEADER** y el **PAYLOAD** sin ingresar ninguna clave:

   ```json
   // HEADER: ALGORITHM & TOKEN TYPE
   {
     "alg": "HS256",
     "typ": "JWT"
   }

   // PAYLOAD: DATA
   {
     "sub": "12",
     "role": "DOCTOR",
     "iat": 1764115200,
     "exp": 1764116100,
     "aud": "hospital-clients",
     "iss": "hospital-api"
   }
   ```

4. Prueba de integridad:
   - Si cambias un solo carácter del segmento intermedio (por ejemplo, intentando modificar `"DOCTOR"` por `"ADMIN"`), `jwt.io` mostrará **Invalid Signature**.
   - Si introduces el mismo `JWT_SECRET` del servidor en la sección **Verify Signature**, `jwt.io` confirmará **Signature Verified** únicamente si el token original permanece intacto.

También puedes comprobar en la terminal de Node.js que el payload es simple Base64URL:

```javascript
const [, payloadSegment] = accessToken.split(".");
const decodedPayload = JSON.parse(
  Buffer.from(payloadSegment, "base64url").toString("utf8"),
);
console.log(decodedPayload);
```

<sub>[⬆ Volver al índice](#contenido)</sub>

---

## 4. Protección de rutas con token y middlewares

Una vez emitido el token, el cliente debe enviarlo en cada petición a recursos protegidos mediante la cabecera estándar HTTP:

```http
GET /api/patients HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Middlewares de autenticación y autorización por roles

Separar la verificación de identidad (`authenticate`) de la evaluación de permisos (`authorize`) mantiene las rutas declarativas y reutilizables:

```javascript
// src/middlewares/auth.middleware.js
import jwt from "jsonwebtoken";

export const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization ?? "";
  const [scheme, token] = authHeader.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      error: {
        code: "UNAUTHENTICATED",
        message: "Authentication token is required",
      },
    });
  }

  try {
    req.auth = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: "hospital-api",
      audience: "hospital-clients",
    });
    return next();
  } catch {
    return res.status(401).json({
      error: {
        code: "INVALID_TOKEN",
        message: "Invalid or expired token",
      },
    });
  }
};

export const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.auth || !allowedRoles.includes(req.auth.role)) {
      return res.status(403).json({
        error: {
          code: "FORBIDDEN",
          message: "Insufficient permissions for this resource",
        },
      });
    }
    return next();
  };
};
```

### Aplicación en las rutas de Hospital API

```javascript
// src/routes/patient.routes.js
import { Router } from "express";
import { authenticate, authorize } from "../middlewares/auth.middleware.js";
import * as PatientController from "../controllers/patient.controller.js";

const patientRouter = Router();

// Todas las rutas de pacientes exigen un usuario autenticado
patientRouter.use(authenticate);

patientRouter.get(
  "/",
  authorize("ADMIN", "DOCTOR", "RECEPTIONIST"),
  PatientController.listPatients,
);
patientRouter.get(
  "/:id",
  authorize("ADMIN", "DOCTOR", "RECEPTIONIST"),
  PatientController.getPatientById,
);
patientRouter.post(
  "/",
  authorize("ADMIN", "RECEPTIONIST"),
  PatientController.createPatient,
);
patientRouter.patch(
  "/:id",
  authorize("ADMIN", "RECEPTIONIST"),
  PatientController.updatePatient,
);
patientRouter.delete(
  "/:id",
  authorize("ADMIN"),
  PatientController.deletePatient,
);

export default patientRouter;
```

### Diferencia entre `401` y `403`

| Código HTTP        | Significado real en la API                         | Cuándo devolverlo                                                           |
| ------------------ | -------------------------------------------------- | --------------------------------------------------------------------------- |
| `401 Unauthorized` | No autenticado: falta identidad válida             | Ausencia de cabecera `Authorization`, firma inválida o token expirado       |
| `403 Forbidden`    | No autorizado: identidad conocida pero sin permiso | Un usuario con rol `RECEPTIONIST` intenta ejecutar `DELETE /api/patients/5` |

<sub>[⬆ Volver al índice](#contenido)</sub>

---

## 5. Obtener información del usuario autenticado

Guardar demasiados datos del usuario dentro del JWT aumenta el tamaño de cada cabecera HTTP y expone información potencialmente desactualizada hasta que el token venza. La práctica recomendada es mantener el JWT liviano (`sub` y `role`) y exponer un endpoint dedicado como `GET /api/auth/me` (o `GET /api/users/me`).

### ¿Para qué sirve `GET /api/auth/me`?

- Permite al cliente (por ejemplo, una aplicación web al recargar la página) reconstruir el estado del perfil actual usando su `accessToken`.
- Obtiene datos frescos desde la base de datos (nombre actualizado, estado activo de la cuenta, correo) sin esperar a reemitir el token.
- Garantiza mediante un **DTO de salida** que campos internos como `passwordHash` jamás abandonen el servidor.

### Implementación del endpoint

```javascript
// En src/controllers/auth.controller.js
export const getAuthenticatedUser = async (req, res, next) => {
  try {
    const userId = Number(req.auth.sub);
    const user = await UserRepository.findPublicProfileById(userId);

    if (!user || !user.isActive) {
      return res.status(401).json({
        error: {
          code: "UNAUTHENTICATED",
          message: "Authenticated user no longer active",
        },
      });
    }

    return res.status(200).json({
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    next(error);
  }
};
```

Flujo de uso:

```text
GET /api/auth/me + Authorization: Bearer <token>
  → middleware authenticate verifica firma y extrae req.auth.sub
  → controlador busca perfil activo en base de datos (sin passwordHash)
  → responde 200 OK con el DTO público del usuario
```

<sub>[⬆ Volver al índice](#contenido)</sub>

---

## 6. Seguridad basada en OWASP Top 10 para REST Security

Proteger una API REST va mucho más allá de agregar un login. El proyecto **OWASP API Security Top 10 (2023)** y la **OWASP REST Security Cheat Sheet** sintetizan las vulnerabilidades más críticas en producción y sus controles concretos en Node.js / Express:

| Riesgo OWASP API Top 10                                            | Qué ocurre cuando falla                                                                                                                       | Mitigación concreta en Hospital API                                                                                               |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **API1:2023 — Broken Object Level Authorization (BOLA)**           | Un usuario autenticado cambia el `{id}` en la URL (`/api/patients/99`) y accede a recursos ajenos a su alcance.                               | Validar pertenencia o alcance de negocio sobre el ID solicitado, no solo que el token exista.                                     |
| **API2:2023 — Broken Authentication**                              | Secretos débiles, ausencia de expiración, aceptación de `alg: "none"` o ataques de fuerza bruta sobre `/api/auth/login`.                      | Fijar `algorithms: ["HS256"]` en `jwt.verify`, `expiresIn` corto, `bcrypt` y _rate limiting_ en `/api/auth/login`.                |
| **API3:2023 — Broken Object Property Level Authorization (BOPLA)** | Exposición de campos sensibles (`passwordHash`) en respuestas o _Mass Assignment_ (`req.body.role = "ADMIN"` al registrarse o editar perfil). | Filtrar campos de entrada con esquemas explícitos y responder siempre mediante DTOs de salida.                                    |
| **API4:2023 — Unrestricted Resource Consumption**                  | Peticiones con _payloads_ gigantes o listados sin límite agotan memoria, CPU o conexiones a base de datos.                                    | Configurar `express.json({ limit: "100kb" })`, paginación con tope máximo y limitadores de tasa (_rate limit_).                   |
| **API5:2023 — Broken Function Level Authorization (BFLA)**         | Endpoints administrativos (`DELETE`, alta de médicos o usuarios) quedan accesibles a roles operativos por omisión del middleware.             | Aplicar `authenticate` por defecto en routers privados y declarar `authorize("ADMIN")` explícitamente en operaciones sensibles.   |
| **API8:2023 — Security Misconfiguration**                          | CORS abierto (`*`) con credenciales, cabeceras inseguras, HTTP sin TLS o trazas internas (_stack traces_) visibles al cliente.                | Exigir HTTPS en producción, usar `helmet`, restringir orígenes en `cors` y devolver errores estandarizados sin detalles internos. |

### Lista mínima de endurecimiento en Express

```javascript
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// 1. Cabeceras HTTP de seguridad y límite de tamaño de body
app.use(helmet());
app.use(express.json({ limit: "100kb" }));

// 2. Limitador específico contra fuerza bruta en autenticación
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: {
      code: "TOO_MANY_REQUESTS",
      message: "Too many login attempts, please try again later",
    },
  },
});

app.use("/api/auth/login", loginLimiter);
```

<sub>[⬆ Volver al índice](#contenido)</sub>

---

## 7. Tarea 015: Autenticación y autorización en Hospital API

> [!IMPORTANT]
> **Objetivo:** evolucionar el proyecto **Hospital API** desarrollado en la Clase 8 incorporando autenticación de usuarios mediante credenciales seguras, autorización de acceso a los recursos protegidos vía **Access Token (JWT)** y actualización completa de la especificación **Swagger / OpenAPI** para autenticar y probar las rutas desde la interfaz interactiva.

### Alcance funcional a implementar

1. **Modelo y persistencia de usuarios:** contar con entidad/tabla de usuarios con `email` único, `passwordHash`, `name`, `role` (`ADMIN`, `DOCTOR`, `RECEPTIONIST`) y estado activo, incluyendo un _seed_ o usuario inicial de prueba con contraseña hasheada.
2. **Endpoints de autenticación:**
   - `POST /api/auth/login`: valida credenciales y emite un `accessToken` firmado con expiración corta.
   - `GET /api/auth/me`: devuelve la información pública del usuario autenticado a partir del token.
3. **Protección de recursos de Hospital API:** proteger los endpoints existentes del hospital (pacientes, médicos, especialidades y demás recursos construidos en la Clase 8) usando los middlewares `authenticate` y `authorize(...roles)`.
4. **Actualización de Swagger / OpenAPI:** documentar `/api/auth/login`, `/api/auth/me`, el esquema de seguridad `bearerAuth` y aplicarlo en los recursos protegidos para poder obtener un `accessToken` y autorizar peticiones directamente desde Swagger UI.

### Configuración de Swagger / OpenAPI para Bearer Token

En la definición OpenAPI 3.0 del proyecto, registra `securitySchemes.bearerAuth` dentro de `components` y vincula `security: [{ bearerAuth: [] }]` en las operaciones protegidas:

```javascript
// Fragmento en src/config/swagger.js (u openapi.yaml equivalente)
export const openApiSpec = {
  openapi: "3.0.3",
  info: {
    title: "Hospital REST API",
    version: "1.1.0",
    description: "Hospital API protegida con autenticación y autorización JWT",
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
        description: "Ingresa el accessToken obtenido en POST /api/auth/login",
      },
    },
  },
  paths: {
    "/api/auth/login": {
      post: {
        tags: ["Auth"],
        summary: "Autenticar usuario y obtener Access Token",
        security: [],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["email", "password"],
                properties: {
                  email: {
                    type: "string",
                    format: "email",
                    example: "admin@hospital.local",
                  },
                  password: {
                    type: "string",
                    format: "password",
                    example: "Admin123!",
                  },
                },
              },
            },
          },
        },
        responses: {
          200: { description: "Login exitoso — devuelve accessToken" },
          401: { description: "Credenciales inválidas" },
        },
      },
    },
    "/api/patients": {
      get: {
        tags: ["Patients"],
        summary: "Listar pacientes (recurso protegido)",
        security: [{ bearerAuth: [] }],
        responses: {
          200: { description: "Listado de pacientes" },
          401: { description: "Token ausente, inválido o expirado" },
          403: { description: "Rol sin permisos suficientes" },
        },
      },
    },
  },
};
```

**Flujo de verificación en Swagger UI (`/api/docs`):**

1. Ejecutar `POST /api/auth/login` con las credenciales de prueba y copiar el valor `accessToken`.
2. Hacer clic en el botón **Authorize** (candado superior derecho en Swagger UI) y pegar el token (sin escribir la palabra `Bearer`, Swagger la antepone automáticamente en esquemas `type: "http", scheme: "bearer"`).
3. Invocar `GET /api/auth/me` y los recursos protegidos de Hospital API verificando respuestas `200`, `401` (sin token) y `403` (con rol insuficiente).

### Criterios de aceptación

- [ ] `POST /api/auth/login` valida credenciales con `bcrypt` y entrega un JWT con `sub`, `role`, `iss`, `aud` y `exp`.
- [ ] Ningún endpoint ni log expone `passwordHash`; las credenciales fallidas devuelven un `401` uniforme.
- [ ] `GET /api/auth/me` retorna los datos públicos del usuario autenticado usando `req.auth.sub`.
- [ ] Los recursos de Hospital API rechazan peticiones sin token o con token vencido/alterado con `401`, y restringen operaciones no permitidas para el rol con `403`.
- [ ] Swagger UI expone la ruta `/api/auth/login`, habilita el botón **Authorize** con esquema `bearerAuth` y marca con candado los endpoints protegidos documentando respuestas `401` y `403`.
- [ ] `JWT_SECRET` reside exclusivamente en `.env` y el archivo `.env.example` documenta las variables requeridas con valores ficticios seguros.

---

### Desafío: Concepto e implementación de Refresh Token

> [!TIP]
> **¿Por qué no alcanza un único Access Token en aplicaciones reales?**
>
> - Si el **Access Token** dura demasiado (por ejemplo, `7d`), su robo compromete la cuenta durante días porque es _stateless_.
> - Si dura poco (por ejemplo, `15m`), obligar al usuario a escribir correo y contraseña cada 15 minutos deteriora la experiencia de uso.
>
> La arquitectura de **Refresh Token** combina seguridad y usabilidad separando responsabilidades en dos tokens distintos.

#### Comparación entre Access Token y Refresh Token

| Característica      | Access Token                                                                  | Refresh Token                                                                                                  |
| ------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| **Propósito**       | Autorizar llamadas a los recursos de la API (`/api/patients`, `/api/doctors`) | Solicitar un nuevo Access Token cuando el anterior expira                                                      |
| **Duración típica** | Corta (`5m` a `15m`)                                                          | Larga (`7d` a `30d`)                                                                                           |
| **Validación**      | _Stateless_ (verificación de firma JWT)                                       | _Stateful_ (se guarda su hash en base de datos para permitir revocación)                                       |
| **Dónde se envía**  | En cada petición a la API (`Authorization: Bearer`)                           | **Solo** a `/api/auth/refresh` y `/api/auth/logout` (idealmente en cookie `HttpOnly; Secure; SameSite=Strict`) |

#### Flujo de rotación y revocación

```mermaid
sequenceDiagram
    participant C as Cliente
    participant API as Hospital API
    participant DB as Tabla refresh_tokens

    C->>API: POST /api/auth/login
    API->>DB: Guardar hash del Refresh Token (userId, expiresAt)
    API-->>C: accessToken (15m) + refreshToken (7d en Cookie HttpOnly)
    Note over C,API: Pasados 15 minutos el accessToken expira (401)
    C->>API: POST /api/auth/refresh (envía refreshToken)
    API->>DB: Verificar que existe, no expiró y no fue revocado
    API->>DB: Revocar token usado y registrar nuevo refreshToken (rotación)
    API-->>C: Nuevo accessToken (15m) + Nuevo refreshToken
    C->>API: POST /api/auth/logout
    API->>DB: Marcar refreshToken como revocado (revokedAt = now)
    API-->>C: 204 No Content (limpia cookie)
```

#### Guía de implementación para el desafío

1. **Persistencia (`refresh_tokens`):** crear un modelo/tabla con `id`, `userId`, `tokenHash` (hash SHA-256 de un token aleatorio generado con `crypto.randomBytes(48).toString("base64url")`), `expiresAt` y `revokedAt`.
2. **Emisión en `/api/auth/login`:** además del `accessToken`, generar el `refreshToken` opaco, persistir su `tokenHash` en base de datos y entregarlo en una cookie `HttpOnly` (o documentar su envío explícito para clientes no navegador).
3. **Renovación con rotación (`POST /api/auth/refresh`):**
   - Hashear el `refreshToken` recibido y buscarlo en `refresh_tokens`.
   - Si no existe, expiró o `revokedAt !== null`, responder `401` (si ya estaba revocado, revocar preventivamente todas las sesiones activas de ese `userId` por posible robo de token).
   - En una transacción: marcar el registro actual con `revokedAt = new Date()`, persistir un nuevo `refreshToken` y devolver un nuevo `accessToken`.
4. **Cierre de sesión real (`POST /api/auth/logout`):** marcar `revokedAt = new Date()` en el registro correspondiente y limpiar la cookie, logrando invalidación efectiva del lado servidor.

<sub>[⬆ Volver al índice](#contenido)</sub>

---

## 8. Referencias

- 📘 [RFC 7519 — JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- 🛠️ [JWT.io Debugger — Inspección y verificación de tokens](https://jwt.io/)
- 📦 [jsonwebtoken — Documentación en npm](https://www.npmjs.com/package/jsonwebtoken)
- 🛡️ [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- 🛡️ [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- 🔐 [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- 📄 [OpenAPI 3.0 — Bearer Authentication](https://swagger.io/docs/specification/v3_0/authentication/bearer-authentication/)

## Mentor

**Ariel Duarte** · Kopius · The Academy

<sub>[⬆ Volver al índice](#contenido)</sub>
