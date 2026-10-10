// ============================================================
// Servidor.java
// Servidor HTTP/HTTPS con API JSON y archivos estáticos.
//
// - Auth via header "Authorization: Bearer <uuid>"
// - Respuestas con código HTTP + cuerpo JSON
// - Sirve el frontend desde la carpeta /public
// - Protecciones: rate limiting, path traversal, IP por sesión,
//   content-type, tamaño máximo de body
// - Handshake: GET /api/handshake devuelve un nonce que el cliente
//   debe devolver en el login para evitar replay
// - HTTPS opcional vía HttpsServer + keystore JKS
// ============================================================
package db;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;

public final class Servidor {

    // ============================================================
    // Configuración
    // ============================================================
    private static final Path PUBLIC_DIR = Paths.get("public");
    private static final Path LOG_SEGURIDAD = Paths.get("logs", "seguridad.log");
    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final int TAMANIO_MAX_BODY = 100 * 1024;

    // Rate limiting de login: 3 intentos por 2 minutos por IP
    private static final int LOGIN_INTENTOS_POR_IP = 3;
    private static final long VENTANA_RATE_LIMIT_MS = 120_000L;

    // Handshake: validez del nonce (5 minutos)
    private static final long NONCE_VALIDEZ_MS = 300_000L;

    // ============================================================
    // Estado
    // ============================================================
    private final Main.Config cfg;
    private final GestorJSON gestor;
    private final Autenticacion auth;
    private HttpServer server;

    // Rate limiting de login
    private final Map<String, List<Long>> intentosLoginPorIP = new HashMap<>();

    // IP original de cada token (para detectar robos)
    private final Map<String, String> ipOriginalDeToken = new HashMap<>();

    // Nonces emitidos y su timestamp de emisión (por IP)
    private final Map<String, Long> noncesEmitidos = new HashMap<>();
    private final Map<String, String> noncePorIP = new HashMap<>();

    private final SecureRandom random = new SecureRandom();

    private Servidor(Main.Config cfg, GestorJSON gestor, Autenticacion auth) {
        this.cfg = cfg;
        this.gestor = gestor;
        this.auth = auth;
    }

    // ============================================================
    // Punto de entrada
    // ============================================================
    public static void iniciar(Main.Config cfg, GestorJSON gestor, Autenticacion auth)
            throws IOException {
        Servidor s = new Servidor(cfg, gestor, auth);
        s.levantar();
    }

    private void levantar() throws IOException {
        int puerto = cfg.puertoEfectivo();
        boolean usarHttps = cfg.httpsEfectivo();

        if (usarHttps) {
            if (cfg.keystorePass == null || cfg.keystorePass.isEmpty()) {
                throw new IOException(
                    "Falta --keystore-pass para arrancar en HTTPS."
                );
            }
            HttpsServer https = HttpsServer.create(new InetSocketAddress(puerto), 0);
            https.setHttpsConfigurator(construirHttpsConfigurator());
            server = https;
        } else {
            server = HttpServer.create(new InetSocketAddress(puerto), 0);
        }

        // Handshake
        server.createContext("/api/handshake", this::handleHandshake);

        // API de autenticación
        server.createContext("/api/login",                 this::handleLogin);
        server.createContext("/api/logout",                this::handleLogout);
        server.createContext("/api/mi-perfil",             this::handleMiPerfil);
        server.createContext("/api/crear-perfil-gratuito", this::handleCrearGratuito);
        server.createContext("/api/consumir-uso",          this::handleConsumirUso);

// API de perfiles
        // API de perfiles
        server.createContext("/api/perfiles",  this::handleListaPerfiles);
        server.createContext("/api/perfil/",   this::handleVerPerfil);

        // API de admin
        server.createContext("/sys/tuvieja1",  this::handleAdminCrear);
        server.createContext("/sys/tuvieja2",        this::handleAdminBanear);
        server.createContext("/sys/tuvieja3",   this::handleAdminCambiarRol);
        server.createContext("/sys/tuvieja4",      this::handleAdminEliminar);
        server.createContext("/sys/tuvieja5",           this::handleAdminLog);
        server.createContext("/sys/tuvieja20",     this::handleAdminGratuitos);
        server.createContext("/sys/tuvieja11",       this::handleAutobanearse);
        server.createContext("/sys/tuviejaca",     this::handleAdminCambiarIP);
        server.createContext("/sis/panel",     this::handleAdminPanel);


        // Catch-all: estáticos
        server.createContext("/", this::handleEstatico);

        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();

        String proto = usarHttps ? "https" : "http";
        System.out.println("[servidor] escuchando en " + proto + "://localhost:" + puerto);
        System.out.println("[servidor] frontend desde " + PUBLIC_DIR.toAbsolutePath());
    }

    // ============================================================
    // HTTPS
    // ============================================================
    private HttpsConfigurator construirHttpsConfigurator() throws IOException {
        Path rutaKs = Paths.get(cfg.keystore);
        if (!Files.exists(rutaKs)) {
            throw new IOException("No existe el keystore: " + rutaKs);
        }

        char[] pass = cfg.keystorePass.toCharArray();

        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            try (InputStream in = Files.newInputStream(rutaKs)) {
                ks.load(in, pass);
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pass);

            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(kmf.getKeyManagers(), null, null);

            return new HttpsConfigurator(ssl);
        } catch (Exception e) {
            throw new IOException("Error cargando keystore: " + e.getMessage(), e);
        } finally {
            java.util.Arrays.fill(pass, '\0');
        }
    }

    // ============================================================
    // ============ HANDSHAKE =====================================
    // ============================================================
    private void handleHandshake(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "GET")) return;

        String ip = obtenerIP(ex);
        limpiarNoncesViejos();

        String nonce = UUID.randomUUID().toString();
        noncesEmitidos.put(nonce, System.currentTimeMillis());
        noncePorIP.put(ip, nonce);

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("nonce", nonce);
        resp.set("version", "1.0");
        resp.set("server", "EmojiForge");
        responderJson(ex, 200, resp);
    }

    private void limpiarNoncesViejos() {
        long corte = System.currentTimeMillis() - NONCE_VALIDEZ_MS;
        noncesEmitidos.entrySet().removeIf(e -> e.getValue() < corte);
        // Los noncePorIP se limpian por referencia en el chequeo
        noncePorIP.entrySet().removeIf(e -> !noncesEmitidos.containsKey(e.getValue()));
    }

    /**
     * Verifica y consume el nonce. Devuelve true si era válido.
     * Un nonce solo se puede usar una vez.
     */
    private boolean consumirNonce(String nonce, String ip) {
        if (nonce == null || nonce.isBlank()) return false;
        Long emitido = noncesEmitidos.remove(nonce);
        if (emitido == null) return false;
        long ahora = System.currentTimeMillis();
        if (ahora - emitido > NONCE_VALIDEZ_MS) return false;
        // Consumirlo también del mapa por IP
        String asignado = noncePorIP.get(ip);
        if (asignado != null && asignado.equals(nonce)) {
            noncePorIP.remove(ip);
        }
        return true;
    }

    // ============================================================
    // ============ HANDLERS DE AUTENTICACIÓN =====================
    // ============================================================

    private void handleLogin(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "POST")) return;

        String ip = obtenerIP(ex);
        if (!puedeIntentarLogin(ip)) {
            responderError(ex, 429, "Demasiados intentos. Esperá un minuto.");
            return;
        }
      
        registrarIntentoLogin(ip);

        Json body;
        try {
            body = leerJsonCuerpo(ex);
        } catch (Exception e) {
            responderError(ex, 400, "JSON inválido");
            return;
        }

        String nombre   = obtenerString(body, "nombre");
        String password = obtenerString(body, "password");
        String nonce    = obtenerString(body, "nonce");

        if (!consumirNonce(nonce, ip)) {
            responderError(ex, 400, "Nonce inválido o expirado");
            return;
        }

        Modelo.Sesion s = auth.login(nombre, password, ip);
        if (s == null) {
            logSeguridad("LOGIN_FALLIDO ip=" + ip + " nombre=" + nombre);
            responderError(ex, 401, "Credenciales incorrectas");
            return;
        }

        ipOriginalDeToken.put(s.token(), ip);

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("token", s.token());
        resp.set("rol", s.rol().etiqueta());
        responderJson(ex, 200, resp);
    }

    private void handleLogout(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "POST")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null) { responderNoEncontrado(ex); return; }

        auth.logout(s.token());
        ipOriginalDeToken.remove(s.token());

        Json resp = Json.object();
        resp.set("ok", true);
        responderJson(ex, 200, resp);
    }

    private void handleCrearGratuito(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "POST")) return;

        String ip = obtenerIP(ex);

        Json body;
        try {
            body = leerJsonCuerpo(ex);
        } catch (Exception e) {
            responderError(ex, 400, "JSON inválido");
            return;
        }

        String nombre   = obtenerString(body, "nombre");
        String password = obtenerString(body, "password");
        String nonce    = obtenerString(body, "nonce");

        if (!consumirNonce(nonce, ip)) {
            responderError(ex, 400, "Nonce inválido o expirado");
            return;
        }

        Modelo.Sesion s = auth.crearPerfilGratuito(nombre, password, ip);
        if (s == null) {
            responderError(ex, 400, "No se pudo crear el perfil");
            return;
        }

        ipOriginalDeToken.put(s.token(), ip);

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("token", s.token());
        resp.set("rol", s.rol().etiqueta());
        responderJson(ex, 201, resp);
    }
    
    

    private void handleConsumirUso(HttpExchange ex) throws IOException {
    if (!exigirMetodo(ex, "POST")) return;

    Modelo.Sesion s = validarSesion(ex);
    if (s == null) { responderNoEncontrado(ex); return; }

    // Solo los gratuitos consumen usos
    if (s.rol() != Modelo.Rol.GRATUITO) {
        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("usosRestantes", -1);   // -1 = ilimitado
        responderJson(ex, 200, resp);
        return;
    }

    // Buscar el perfil gratuito
    Modelo.PerfilGratuito g = gestor.leerPerfilGratuito(s.perfilId());
    if (g == null) {
        responderError(ex, 404, "Perfil no encontrado");
        return;
    }

    // ¿Tiene usos?
    if (!g.puedeUsar()) {
        responderError(ex, 403, "Sin usos restantes");
        return;
    }

    // Consumir un uso
    try {
        g.consumirUso("empaquetar");
    } catch (Exception e) {
        responderError(ex, 403, "Sin usos restantes");
        return;
    }

    // Guardar el cambio
    gestor.actualizarPerfilGratuito(g);

    Json resp = Json.object();
    resp.set("ok", true);
    resp.set("usosRestantes", g.usosRestantes());
    responderJson(ex, 200, resp);
}
    
    private void handleMiPerfil(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "GET")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null) { responderNoEncontrado(ex); return; }

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("perfilId", s.perfilId());
        resp.set("rol", s.rol().etiqueta());

        if (s.rol() == Modelo.Rol.GRATUITO) {
            Modelo.PerfilGratuito g = gestor.leerPerfilGratuito(s.perfilId());
            if (g != null) {
                resp.set("nombre", g.nombre());
                resp.set("usosRestantes", g.usosRestantes());
                resp.set("estado", g.estado().name());
            }
        } else {
            Modelo.Perfil p = buscarPerfilPorId(s.perfilId());
            if (p != null) {
                resp.set("nombre", p.nombre());
                resp.set("estado", p.estado().name());
            }
        }

        responderJson(ex, 200, resp);
    }

    // ============================================================
    // ============ HANDLERS DE PERFILES ==========================
    // ============================================================

    private void handleListaPerfiles(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "GET")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null) { responderNoEncontrado(ex); return; }

        if (!Roles.puedeVerLista(s)) {
            responderNoEncontrado(ex);
            return;
        }

        Json arr = Json.array();
        for (Modelo.EntradaIndice e : gestor.listarTodos()) {
            Json item = Json.object();
            item.set("nombre", e.nombre());
            item.set("rol", e.rol().etiqueta());
            item.set("estado", e.estado().name());
            arr.add(item);
        }

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("perfiles", arr);
        responderJson(ex, 200, resp);
    }

    private void handleVerPerfil(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "GET")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null) { responderNoEncontrado(ex); return; }

        String ruta = ex.getRequestURI().getPath();
        String id = ruta.substring("/api/perfil/".length());
        if (id.isBlank()) { responderNoEncontrado(ex); return; }

        Modelo.Perfil objetivo = buscarPerfilPorId(id);
        if (objetivo == null) {
            Modelo.PerfilGratuito g = gestor.leerPerfilGratuito(id);
            if (g == null) { responderNoEncontrado(ex); return; }
            if (!s.perfilId().equals(g.id()) && !Roles.puedeVerOtros(s)) {
                responderNoEncontrado(ex);
                return;
            }
            Json resp = Json.object();
            resp.set("ok", true);
            resp.set("nombre", g.nombre());
            resp.set("rol", "GRATUITO");
            resp.set("estado", g.estado().name());
            responderJson(ex, 200, resp);
            return;
        }

        if (!Roles.puedeSobre(s, Roles.Accion.VER_PERFIL_AJENO, objetivo)) {
            responderNoEncontrado(ex);
            return;
        }

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("id", objetivo.id());
        resp.set("nombre", objetivo.nombre());
        resp.set("rol", objetivo.rol().etiqueta());
        resp.set("estado", objetivo.estado().name());
        responderJson(ex, 200, resp);
    }

    // ============================================================
    // ============ HANDLERS DE ADMIN =============================
    // ============================================================

    private void handleAdminCrear(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "POST")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return; }

        Json body;
        try { body = leerJsonCuerpo(ex); }
        catch (Exception e) { responderError(ex, 400, "JSON inválido"); return; }

        String nombre   = obtenerString(body, "nombre");
        String password = obtenerString(body, "password");
        String rolStr   = obtenerString(body, "rol");

        Modelo.Rol rol = Modelo.Rol.desdeNombre(rolStr);
        if (rol == null || rol == Modelo.Rol.GRATUITO) {
            responderError(ex, 400, "Rol inválido");
            return;
        }

        String salt = Cifrado.generarSaltHex();
        String hash = Cifrado.hashearPassword(password, salt);

        Modelo.Perfil p;
        try {
            p = gestor.crearPerfilPro(nombre, rol, hash, salt, obtenerIP(ex));
        } catch (Exception e) {
            responderError(ex, 400, e.getMessage());
            return;
        }

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("id", p.id());
        resp.set("nombre", p.nombre());
        resp.set("rol", p.rol().etiqueta());
        responderJson(ex, 201, resp);
    }

    private void handleAdminBanear(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "POST")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return; }

        Json body;
        try { body = leerJsonCuerpo(ex); }
        catch (Exception e) { responderError(ex, 400, "JSON inválido"); return; }

        String nombre = obtenerString(body, "nombre");
        String motivo = obtenerString(body, "motivo");

        Modelo.Perfil objetivo = gestor.leerPerfil(nombre);
        if (objetivo == null) { responderNoEncontrado(ex); return; }

        if (!Roles.puedeSobre(s, Roles.Accion.BANEAR, objetivo)) {
            responderNoEncontrado(ex);
            return;
        }

        objetivo.setEstado(Modelo.Estado.BANEADO);
        gestor.actualizarPerfil(objetivo);
        gestor.agregarBaneado(
            Modelo.Baneado.nuevo(objetivo.id(), objetivo.ipCreacion(), motivo)
        );
        auth.cerrarTodasDe(objetivo.id());

        Json resp = Json.object();
        resp.set("ok", true);
        responderJson(ex, 200, resp);
    }

    private void handleAdminCambiarRol(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "POST")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return; }

        Json body;
        try { body = leerJsonCuerpo(ex); }
        catch (Exception e) { responderError(ex, 400, "JSON inválido"); return; }

        String nombre = obtenerString(body, "nombre");
        String rolStr = obtenerString(body, "rol");

        Modelo.Perfil objetivo = gestor.leerPerfil(nombre);
        if (objetivo == null) { responderNoEncontrado(ex); return; }

        Modelo.Rol nuevoRol = Modelo.Rol.desdeNombre(rolStr);
        if (nuevoRol == null || nuevoRol == Modelo.Rol.GRATUITO) {
            responderError(ex, 400, "Rol inválido");
            return;
        }

        try {
            objetivo.setRol(nuevoRol);
        } catch (Exception e) {
            responderError(ex, 400, e.getMessage());
            return;
        }
        gestor.actualizarPerfil(objetivo);

        Json resp = Json.object();
        resp.set("ok", true);
        responderJson(ex, 200, resp);
    }

    private void handleAdminEliminar(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "POST")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return; }

        Json body;
        try { body = leerJsonCuerpo(ex); }
        catch (Exception e) { responderError(ex, 400, "JSON inválido"); return; }

        String nombre = obtenerString(body, "nombre");
        Modelo.Perfil objetivo = gestor.leerPerfil(nombre);
        if (objetivo == null) { responderNoEncontrado(ex); return; }

        if (!Roles.puedeSobre(s, Roles.Accion.ELIMINAR, objetivo)) {
            responderNoEncontrado(ex);
            return;
        }

        auth.cerrarTodasDe(objetivo.id());
        gestor.eliminarPerfil(nombre);

        Json resp = Json.object();
        resp.set("ok", true);
        responderJson(ex, 200, resp);
    }

    private void handleAdminLog(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "GET")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return; }

        String contenido = Roles.leerLogSeguridad(s);
        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("log", contenido);
        responderJson(ex, 200, resp);
    }

    private void handleAdminGratuitos(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "GET")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return; }

        Json arr = Json.array();
        for (Modelo.PerfilGratuito g : gestor.listarGratuitos()) {
            Json item = Json.object();
            item.set("id", g.id());
            item.set("nombre", g.nombre());
            item.set("usosRestantes", g.usosRestantes());
            item.set("estado", g.estado().name());
            item.set("ipCreacion", g.ipCreacion());
            item.set("fechaCreacion", g.fechaCreacion());
            arr.add(item);
        }

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("gratuitos", arr);
        responderJson(ex, 200, resp);
    }

    private void handleAutobanearse(HttpExchange ex) throws IOException {
        if (!exigirMetodo(ex, "POST")) return;

        Modelo.Sesion s = validarSesion(ex);
        if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return; }

        Json body;
        try { body = leerJsonCuerpo(ex); }
        catch (Exception e) { body = Json.object(); }

        String motivo = obtenerString(body, "motivo");

        boolean ok = Roles.autobanearse(s, gestor, auth, motivo);
        if (!ok) { responderError(ex, 500, "No se pudo autobanear"); return; }

        Json resp = Json.object();
        resp.set("ok", true);
        resp.set("mensaje", "Adiós, admin. Fue un placer.");
        responderJson(ex, 200, resp);
    }

private void handleAdminCambiarIP(HttpExchange ex) throws IOException{

if (!exigirMetodo(ex, "POST")) return;
Modelo.Sesion s = validarSesion(ex);
if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return;}

Json body;
try { body = leerJsonCuerpo(ex); }
catch (Exception e) { responderError(ex, 400, "JSON inválido"); return;}
   
String nuevaIP = obtenerString(body, "ip");
if (nuevaIP.isBlank()) { responderError(ex, 400, "IP vacía"); return;}

Modelo.Perfil admin = buscarPerfilPorId(s.perfilId());
if (admin == null) { responderNoEncontrado(ex); return;}

gestor.cambiarIP(admin.nombre(), nuevaIP);

Json resp = Json.object();
resp.set("ok", true);
resp.set("ip", nuevaIP);
responderJson(ex, 200, resp);
}


// PANELH

private void handleAdminPanel(HttpExchange ex) throws IOException {
    if (!exigirMetodo(ex, "GET")) return;
    Modelo.Sesion s = validarSesion(ex);
    if (s == null || !Roles.esAdmin(s)) { responderNoEncontrado(ex); return; }
    
    // Leer el HTML del panel desde un archivo
    Path archivo = Paths.get("src", "db", "admin.html");
    if (!Files.exists(archivo)) { responderNoEncontrado(ex); return; }
    
    String html = new String(Files.readAllBytes(archivo), StandardCharsets.UTF_8);
    
    Json resp = Json.object();
    resp.set("ok", true);
    resp.set("html", html);
    responderJson(ex, 200, resp);
}


    // ============================================================
    // ============ ARCHIVOS ESTÁTICOS ============================
    // ============================================================

    private void handleEstatico(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) {
            responderError(ex, 405, "Método no permitido");
            return;
        }

        String ruta = ex.getRequestURI().getPath();
        if (ruta == null || ruta.isBlank() || ruta.equals("/")) {
            ruta = "/index.html";
        }

        if (ruta.startsWith("/")) ruta = ruta.substring(1);

        if (ruta.contains("..") || ruta.contains("\\") || ruta.contains("\0")) {
            responderNoEncontrado(ex);
            return;
        }
        if (ruta.startsWith(".") || ruta.contains("/.")) {
            responderNoEncontrado(ex);
            return;
        }

        Path archivo = PUBLIC_DIR.resolve(ruta).normalize();
        Path base = PUBLIC_DIR.toAbsolutePath().normalize();
        if (!archivo.toAbsolutePath().normalize().startsWith(base)) {
            responderNoEncontrado(ex);
            return;
        }
        if (!Files.exists(archivo) || !Files.isRegularFile(archivo)) {
            responderNoEncontrado(ex);
            return;
        }

        byte[] datos = Files.readAllBytes(archivo);
Headers h = ex.getResponseHeaders();
h.set("Content-Type", mimeDe(ruta));
h.set("X-Content-Type-Options", "nosniff");
h.set("Cache-Control", "no-cache");
h.set("X-Frame-Options", "DENY");
h.set("Referrer-Policy", "strict-origin-when-cross-origin");
h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
h.set("Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self'; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: blob:; " +
    "media-src 'self' blob:; " +
    "connect-src 'self'; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'none'; " +
    "frame-ancestors 'none'; " +
    "upgrade-insecure-requests");
if (cfg.httpsEfectivo()) {
    h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}
ex.sendResponseHeaders(200, datos.length);
try (OutputStream os = ex.getResponseBody()) {
    os.write(datos);
}
    }

    private String mimeDe(String ruta) {
        String r = ruta.toLowerCase();
        if (r.endsWith(".html") || r.endsWith(".htm")) return "text/html; charset=utf-8";
        if (r.endsWith(".css")) return "text/css; charset=utf-8";
        if (r.endsWith(".js"))  return "application/javascript; charset=utf-8";
        if (r.endsWith(".json")) return "application/json; charset=utf-8";
        if (r.endsWith(".svg")) return "image/svg+xml";
        if (r.endsWith(".png")) return "image/png";
        if (r.endsWith(".jpg") || r.endsWith(".jpeg")) return "image/jpeg";
        if (r.endsWith(".gif")) return "image/gif";
        if (r.endsWith(".webp")) return "image/webp";
        if (r.endsWith(".ico")) return "image/x-icon";
        if (r.endsWith(".woff")) return "font/woff";
        if (r.endsWith(".woff2")) return "font/woff2";
        return "application/octet-stream";
    }

    // ============================================================
    // ============ HELPERS =======================================
    // ============================================================

    private boolean exigirMetodo(HttpExchange ex, String metodo) throws IOException {
        if (!metodo.equals(ex.getRequestMethod())) {
            responderError(ex, 405, "Método no permitido");
            return false;
        }
        return true;
    }

    private Json leerJsonCuerpo(HttpExchange ex) throws IOException {
        String contentType = ex.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase().startsWith("application/json")) {
            throw new Json.JsonException("Content-Type debe ser application/json");
        }

        InputStream in = ex.getRequestBody();
        byte[] buf = new byte[8192];
        java.io.ByteArrayOutputStream acumulador = new java.io.ByteArrayOutputStream();
        int total = 0;
        int leidos;
        while ((leidos = in.read(buf)) > 0) {
            total += leidos;
            if (total > TAMANIO_MAX_BODY) {
                throw new Json.JsonException("Body demasiado grande");
            }
            acumulador.write(buf, 0, leidos);
        }
        String texto = acumulador.toString(StandardCharsets.UTF_8);
        if (texto.isBlank()) return Json.object();
        return Json.parse(texto);
    }

    private String obtenerString(Json j, String clave) {
        if (j == null) return "";
        Json v = j.get(clave);
        if (v == null) return "";
        return v.asString("");
    }

    private void responderJson(HttpExchange ex, int status, Json cuerpo) throws IOException {
    byte[] datos = cuerpo.toString().getBytes(StandardCharsets.UTF_8);
    Headers h = ex.getResponseHeaders();
    h.set("Content-Type", "application/json; charset=utf-8");
    h.set("X-Content-Type-Options", "nosniff");
    h.set("X-Frame-Options", "DENY");
    h.set("Referrer-Policy", "strict-origin-when-cross-origin");
    h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    h.set("Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: blob:; " +
        "media-src 'self' blob:; " +
        "connect-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'none'; " +
        "frame-ancestors 'none'; " +
        "upgrade-insecure-requests");
    if (cfg.httpsEfectivo()) {
        h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    ex.sendResponseHeaders(status, datos.length);
    try (OutputStream os = ex.getResponseBody()) {
        os.write(datos);
    }
}

    private void responderError(HttpExchange ex, int status, String mensaje) throws IOException {
        Json resp = Json.object();
        resp.set("ok", false);
        resp.set("error", mensaje);
        responderJson(ex, status, resp);
    }

    private void responderNoEncontrado(HttpExchange ex) throws IOException {
        responderError(ex, 404, "No encontrado");
    }

    private String obtenerIP(HttpExchange ex) {
        String xff = ex.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int coma = xff.indexOf(',');
            return coma > 0 ? xff.substring(0, coma).trim() : xff.trim();
        }
        return ex.getRemoteAddress().getAddress().getHostAddress();
    }

    private Modelo.Sesion validarSesion(HttpExchange ex) {
        String header = ex.getRequestHeaders().getFirst("Authorization");
        if (header == null || header.isBlank()) return null;
        if (!header.startsWith("Bearer ")) return null;
        String token = header.substring("Bearer ".length()).trim();
        if (token.isEmpty()) return null;

        Modelo.Sesion s = auth.validar(token);
        if (s == null) return null;

        String ip = obtenerIP(ex);
        String original = ipOriginalDeToken.get(token);
        if (original == null) {
            ipOriginalDeToken.put(token, ip);
        } else if (!original.equals(ip)) {
            logSeguridad("IP_CAMBIANTE token=" + token
                + " ipOriginal=" + original + " ipActual=" + ip);
            ipOriginalDeToken.put(token, ip);
        }
        return s;
    }

    private Modelo.Perfil buscarPerfilPorId(String id) {
        for (Modelo.EntradaIndice e : gestor.listarTodos()) {
            Modelo.Perfil p = gestor.leerPerfil(e.nombre());
            if (p != null && p.id().equals(id)) return p;
        }
        return null;
    }

    // ============================================================
    // ============ RATE LIMITING DE LOGIN ========================
    // ============================================================

    private boolean puedeIntentarLogin(String ip) {
        long ahora = System.currentTimeMillis();
        limpiarIntentos(ahora);
        List<Long> veces = intentosLoginPorIP.get(ip);
        return veces == null || veces.size() < LOGIN_INTENTOS_POR_IP;
    }

    private void registrarIntentoLogin(String ip) {
        long ahora = System.currentTimeMillis();
        intentosLoginPorIP.computeIfAbsent(ip, k -> new ArrayList<>()).add(ahora);
    }

    private void limpiarIntentos(long ahora) {
        long corte = ahora - VENTANA_RATE_LIMIT_MS;
        for (List<Long> l : intentosLoginPorIP.values()) {
            l.removeIf(t -> t < corte);
        }
        intentosLoginPorIP.entrySet().removeIf(e -> e.getValue().isEmpty());
    }

    // ============================================================
    // ============ LOG DE SEGURIDAD ==============================
    // ============================================================

    private void logSeguridad(String msg) {
        try {
            Files.createDirectories(LOG_SEGURIDAD.getParent());
            String linea = LocalDateTime.now().format(FMT) + " [servidor] " + msg + "\n";
            Files.write(
                LOG_SEGURIDAD,
                linea.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            System.err.println("[servidor] no se pudo escribir log: " + e.getMessage());
        }
    }

    
}