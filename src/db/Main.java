// ============================================================
// Main.java
// Punto de entrada del servidor.
//
// Arranca en orden:
//   1. Cifrado (clave maestra)
//   2. GestorJSON (índice, baneados, nombres gratuitos)
//   3. Admin inicial (si no existe)
//   4. Autenticación
//   5. Servidor HTTP/HTTPS
//
// Modos:
//   --modo=pruebas     (8080 HTTP, default)
//   --modo=produccion  (8443 HTTPS)
//   --modo=emergencia  (9090 HTTP)
//
// Ejemplos:
//   java db.Main
//   java db.Main --modo=produccion --keystore-pass=secreto
//   java db.Main --puerto=9000
//   java db.Main --ayuda
// ============================================================
package db;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class Main {

    // ============================================================
    // Puertos por modo
    // ============================================================
    private static final int PUERTO_PRUEBAS    = 7721;
    private static final int PUERTO_PRODUCCION = 8043;
    private static final int PUERTO_EMERGENCIA = 9440;

    // ============================================================
    // Configuración
    // ============================================================
    public static final class Config {
        public String  modo         = "pruebas";
        public Integer puerto       = null;
        public Boolean https        = null;
        public String  keystore     = "certs/keystore.jks";
        public String  keystorePass = null;
        public String  adminNombre  = null;
        public String  adminPass    = null;
        public boolean silencioso   = false;
        public boolean ayuda        = false;

        public int puertoEfectivo() {
            if (puerto != null) return puerto;
            return switch (modo) {
                case "produccion" -> PUERTO_PRODUCCION;
                case "emergencia" -> PUERTO_EMERGENCIA;
                default           -> PUERTO_PRUEBAS;
            };
        }

        public boolean httpsEfectivo() {
            if (https != null) return https;
            return "produccion".equals(modo);
        }
    }

    // ============================================================
    // Punto de entrada
    // ============================================================
    public static void main(String[] args) {
        var cfg = parsear(args);

        if (cfg.ayuda) {
            imprimirAyuda();
            return;
        }

        imprimirCabecera(cfg);

        if (!iniciarCifrado(cfg)) {
            System.exit(1);
            return;
        }

        var gestor = iniciarGestor(cfg);
        if (gestor == null) {
            System.exit(1);
            return;
        }

        if (!crearAdminInicial(cfg, gestor)) {
            System.exit(1);
            return;
        }

        var auth = new Autenticacion(gestor);
        log(cfg, "[main] autenticación OK");

        iniciarServidor(cfg, gestor, auth);
    }

    // ============================================================
    // Arranque paso a paso
    // ============================================================

    private static void imprimirCabecera(Config cfg) {
        log(cfg, "════════════════════════════════════════════════");
        log(cfg, "  Iniciando servidor EmojiForge");
        log(cfg, "  Modo: " + cfg.modo);
        log(cfg, "  Puerto: " + cfg.puertoEfectivo());
        log(cfg, "  Protocolo: " + (cfg.httpsEfectivo() ? "HTTPS" : "HTTP"));
        log(cfg, "════════════════════════════════════════════════");
    }

    private static boolean iniciarCifrado(Config cfg) {
        try {
            Cifrado.arrancar(false);
            log(cfg, "[main] cifrado OK");
            return true;
        } catch (Exception e) {
            System.err.println("[main] ERROR arrancando cifrado: " + e.getMessage());
            return false;
        }
    }

    /**
     * Arranca el gestor. Si no hay índice (primer arranque) o está
     * corrupto, arranca con un índice vacío en lugar de morir.
     */
    private static GestorJSON iniciarGestor(Config cfg) {
        var gestor = new GestorJSON();
        try {
            gestor.arrancar();
            log(cfg, "[main] gestor OK");
            return gestor;
        } catch (Exception e) {
            log(cfg, "[main] índice no disponible: " + e.getMessage());
            log(cfg, "[main] arrancando con índice vacío");
        }
        try {
            gestor.arrancarIgnorandoIndice();
            log(cfg, "[main] gestor OK (índice nuevo)");
            return gestor;
        } catch (Exception e2) {
            System.err.println("[main] ERROR arrancando gestor: " + e2.getMessage());
            return null;
        }
    }

    private static boolean crearAdminInicial(Config cfg, GestorJSON gestor) {
        try {
            crearAdminSiNoExiste(cfg, gestor);
            return true;
        } catch (Exception e) {
            System.err.println("[main] ERROR con el admin inicial: " + e.getMessage());
            return false;
        }
    }

    private static void iniciarServidor(Config cfg, GestorJSON gestor, Autenticacion auth) {
        log(cfg, "[main] arrancando servidor...");
        try {
            Servidor.iniciar(cfg, gestor, auth);
        } catch (Exception e) {
            System.err.println("[main] ERROR arrancando servidor: " + e.getMessage());
            System.exit(1);
        }
    }

    // ============================================================
    // Admin inicial
    // ============================================================
    private static void crearAdminSiNoExiste(Config cfg, GestorJSON gestor) {
        if (gestor.existeAdmin()) {
            log(cfg, "[main] admin ya existe, no se crea de nuevo");
            return;
        }

        log(cfg, "[main] no hay admin. Creando admin inicial.");

        String nombre = cfg.adminNombre;
        if (nombre == null || nombre.isBlank()) {
            nombre = leerLinea("Nombre del admin: ");
            if (nombre == null || nombre.isBlank()) {
                throw new Json.JsonException("Nombre de admin vacío.");
            }
        }

        String password = cfg.adminPass;
        if (password == null || password.isEmpty()) {
            password = leerPassword("Contraseña del admin: ");
            String conf = leerPassword("Confirmá la contraseña: ");
            if (!password.equals(conf)) {
                throw new Json.JsonException("Las contraseñas no coinciden.");
            }
        }

        String salt = Cifrado.generarSaltHex();
        String hash = Cifrado.hashearPassword(password, salt);

        Modelo.Perfil admin = gestor.crearAdminInicial(nombre, hash, salt);

        log(cfg, "[main] admin creado: " + admin.nombre()
            + " (id=" + admin.id() + ")");
        System.out.println("───────────────────────────────────────────────");
        System.out.println("  Guardá estas credenciales en un lugar seguro.");
        System.out.println("  Nombre: " + admin.nombre());
        System.out.println("  No hay recuperación por web. Si las perdés,");
        System.out.println("  hay que recuperar desde el servidor a mano.");
        System.out.println("───────────────────────────────────────────────");
    }

    // ============================================================
    // Lectura por consola
    // ============================================================
    private static String leerLinea(String prompt) {
        Console c = System.console();
        if (c != null) return c.readLine(prompt);
        System.out.print(prompt);
        try {
            byte[] buf = new byte[512];
            int n = System.in.read(buf);
            if (n <= 0) return "";
            int fin = n;
            while (fin > 0 && (buf[fin - 1] == '\n' || buf[fin - 1] == '\r')) fin--;
            return new String(buf, 0, fin, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    private static String leerPassword(String prompt) {
        Console c = System.console();
        if (c != null) {
            char[] p = c.readPassword(prompt);
            if (p == null) return "";
            String s = new String(p);
            Arrays.fill(p, '\0');
            return s;
        }
        return leerLinea(prompt);
    }

    // ============================================================
    // Parseo de argumentos
    // ============================================================
    private static Config parsear(String[] args) {
        var cfg = new Config();
        if (args == null) return cfg;

        for (String a : args) {
            if (a == null || !a.startsWith("--")) continue;
            String cuerpo = a.substring(2);
            int eq = cuerpo.indexOf('=');
            String clave = eq >= 0 ? cuerpo.substring(0, eq) : cuerpo;
            String valor = eq >= 0 ? cuerpo.substring(eq + 1) : "";

            switch (clave) {
                case "modo"          -> aplicarModo(cfg, valor);
                case "puerto"        -> aplicarPuerto(cfg, valor);
                case "http"          -> cfg.https = false;
                case "https"         -> cfg.https = true;
                case "keystore"      -> cfg.keystore = valor;
                case "keystore-pass" -> cfg.keystorePass = valor;
                case "admin-nombre"  -> cfg.adminNombre = valor;
                case "admin-pass"    -> cfg.adminPass = valor;
                case "silencioso"    -> cfg.silencioso = true;
                case "ayuda", "help", "h" -> cfg.ayuda = true;
                default -> System.err.println("[main] argumento desconocido: --" + clave);
            }
        }
        return cfg;
    }

    private static void aplicarModo(Config cfg, String valor) {
        switch (valor) {
            case "pruebas", "produccion", "emergencia" -> cfg.modo = valor;
            default -> System.err.println("[main] modo desconocido: " + valor);
        }
    }

    private static void aplicarPuerto(Config cfg, String valor) {
        try {
            cfg.puerto = Integer.parseInt(valor);
        } catch (NumberFormatException e) {
            System.err.println("[main] puerto inválido: " + valor);
        }
    }

    // ============================================================
    // Ayuda
    // ============================================================
    private static void imprimirAyuda() {
        System.out.println();
        System.out.println("EmojiForge — servidor");
        System.out.println();
        System.out.println("Uso:");
        System.out.println("  java db.Main [opciones]");
        System.out.println();
        System.out.println("Modos:");
        System.out.println("  --modo=pruebas      Puerto 8080, HTTP    (default)");
        System.out.println("  --modo=produccion   Puerto 8443, HTTPS");
        System.out.println("  --modo=emergencia   Puerto 9090, HTTP");
        System.out.println();
        System.out.println("Opciones:");
        System.out.println("  --puerto=N              Pisa el puerto del modo");
        System.out.println("  --http / --https        Pisa el protocolo del modo");
        System.out.println("  --keystore=RUTA         Ruta al keystore JKS (solo HTTPS)");
        System.out.println("  --keystore-pass=XXX     Contraseña del keystore");
        System.out.println("  --admin-nombre=X        Nombre del admin inicial (opcional)");
        System.out.println("  --admin-pass=Y          Contraseña del admin (opcional, no recomendado)");
        System.out.println("  --silencioso            No imprimir log de arranque");
        System.out.println("  --ayuda                 Mostrar esta ayuda");
        System.out.println();
        System.out.println("Ejemplos:");
        System.out.println("  java db.Main");
        System.out.println("  java db.Main --modo=produccion --keystore-pass=secreto");
        System.out.println("  java db.Main --puerto=9000");
        System.out.println("  java db.Main --admin-nombre=admin");
        System.out.println();
    }

    // ============================================================
    // Log
    // ============================================================
    private static void log(Config cfg, String msg) {
        if (cfg != null && cfg.silencioso) return;
        System.out.println(msg);
    }

    private Main() {}
}