# EmojiForge

EmojiForge es un proyecto de **esteganografía** que consiste en poder mover múltiples archivos, independientemente de su tipo, dentro de emojis, palabras o espacios vacíos.

## Cómo funciona

La herramienta codifica un archivo —sea del tipo que sea— en su secuencia de bytes, le aplica CRC32 y lo empaqueta con un header. Después tiene la opción de cifrarlo con un cifrado casero que imita AES-256, y que puede cifrar tanto el payload como los bytes por separado.

Todo esto se hace únicamente con HTML + CSS + JS. Sin frameworks, sin dependencias externas.

### Empaquetado

1. Agarrás el archivo (imagen, video, texto, URL, lo que sea).
2. Se lee como bytes.
3. Se le calcula CRC32.
4. Se arma el payload con un header (magic `EMFG`, versión, flags, salt).
5. Opcionalmente se cifra.
6. Opcionalmente se comprime.
7. Cada byte se codifica en un carácter invisible (variation selector o tag char).
8. Los caracteres van dentro de un emoji visible.

### Extracción

El proceso inverso. Se decodifican los caracteres, se descifra si corresponde, se descomprime, y se reconstruyen los archivos. El CRC32 confirma que llegaron intactos.

## Seguridad

Sin duda, el punto más importante no solo del backend sino de toda la herramienta. Es lo que más me pone orgulloso.

### Cifrado

- **Contraseñas de usuario**: PBKDF2 con SHA-256, 200.000 iteraciones, salt de 32 bytes.
- **Perfiles**: AES-GCM con clave derivada por perfil. El ID del perfil se usa como AAD, así que un archivo no se puede mover a otro perfil.
- **Clave maestra**: cifrada con contraseña. La contraseña vive en un archivo aparte con permisos restrictivos, fuera del repositorio.
- **Clave interna por perfil**: derivada al vuelo desde el ID + clave maestra. No se guarda en disco.
- **Cifrado casero** para el payload: tres capas que imitan AES-256, puede cifrar tanto los bytes de cada archivo como el payload completo.

### Autenticación

- Login con nombre y contraseña.
- Verificación en tiempo constante (evita enumeración de usuarios).
- Nonce de un solo uso con TTL de 5 minutos, previene replay.
- Token en `sessionStorage`, no en cookies.
- Máximo 2 sesiones activas por perfil.

### Autorización

- Roles: GRATUITO, PRO, EDITOR, NIVEL3, ADMIN.
- Cada acción tiene un rol mínimo.
- Chequeo server-side en cada endpoint.
- Admin único: no se puede crear un segundo.
- Panel admin servido por endpoint protegido, no en el HTML.

### Protección del servidor

- Rate limiting de login (3 intentos por IP cada 2 minutos).
- Delay creciente por IP en endpoints de autenticación.
- Headers HTTP: CSP, HSTS, X-Frame-Options, Referrer-Policy.
- Path traversal bloqueado en estáticos.
- Límite de 100 KB en el body de las requests.
- Rutas de fachada para el panel admin.

### Seguridad del frontend

Esto es algo que aprendí hace poco: el frontend también tiene que tener su propio nivel de seguridad. Una capa extra contra inyecciones XSS.

- Interpretar el input del usuario como eso, texto. Siempre.
- Evitar usar `innerHTML` con contenido del usuario. Se usa `textContent`.
- Archivos como `seguridad.js` se encargan de que el frontend solo se pueda comunicar con cierta cantidad de archivos.
- `tapa.js` maneja la comunicación con la API, con el token en `sessionStorage`.
- `admin.js` carga el panel admin solo si el rol es ADMIN, y solo si el server lo autoriza.
- CSP aplicado desde el server, que refuerza todo lo anterior.

## Estructura

### Backend (Java)

8 archivos. Nada más. Sin frameworks, sin dependencias externas, sin Maven ni Gradle. Todo lo que hace el servidor vive acá:

- **Main.java** → arranca todo en orden: cifrado, gestor, admin inicial, servidor. Parsea los argumentos de línea de comandos.
- **Json.java** → parser y serializador JSON propio. Estricto, sin dependencias.
- **Cifrado.java** → PBKDF2, AES-GCM, clave maestra, rotación. Toda la criptografía.
- **GestorJSON.java** → lee y escribe los archivos cifrados. Índice con checksum, backup automático, rate limiting de registro.
- **Modelo.java** → Perfil, PerfilGratuito, Indice, Sesion, Baneado, Rol. Solo la forma de los datos.
- **Autenticacion.java** → login, sesiones, nonce. El pegamento entre el frontend y el gestor.
- **Roles.java** → permisos por rol. Autobaneo incluido, porque por qué no.
- **Servidor.java** → HTTP/HTTPS, endpoints, headers de seguridad, panel admin por backend.
- **admin.html** → el HTML del panel admin. No vive en `public/` porque no tiene por qué verlo cualquiera.

