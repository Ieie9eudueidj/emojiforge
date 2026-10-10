// ============================================================
// Autenticacion.java
// Login, creación de perfiles gratuitos, sesiones y logout.
//
// NO hashea (eso lo hace Cifrado).
// NO cifra (eso lo hace Cifrado).
// NO toca archivos (eso lo hace GestorJSON).
// NO decide permisos (eso lo hace Roles, más adelante).
//
// Este archivo es el pegamento: recibe nombre+contraseña,
// verifica contra el perfil correspondiente, emite un token
// de sesión, y maneja la lista de sesiones activas en memoria.
//
// Reglas implementadas:
//   - Sesión en memoria del servidor (opción A).
//   - Sin expiración automática (opción D, vulnerabilidad puesta a propósito).
//   - Tiempo constante en login: nombres inexistentes también hashean.
//   - Máximo 2 sesiones activas por perfil (opción B).
//   - Logout marca inactiva, no borra (opción A).
//   - Detección de tokens modificados por validación de UUID.
// ============================================================
package db;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class Autenticacion {

    private static final int MAX_SESIONES_POR_PERFIL = 2;

    // Salt fijo de "relleno" para hacer tiempo constante cuando el
    // perfil no existe. Se calcula una sola vez.
    private static final String SALT_FICTICIO = Cifrado.generarSaltHex();
    private static final String HASH_FICTICIO =
        Cifrado.hashearPassword("dummy-password-para-tiempo-constante", SALT_FICTICIO);

    private final GestorJSON gestor;
    private final Map<String, Modelo.Sesion> sesiones;  // token -> sesión

    // ============================================================
    // Constructor
    // ============================================================
    public Autenticacion(GestorJSON gestor) {
        if (gestor == null) throw new Json.JsonException("Gestor nulo");
        this.gestor = gestor;
        this.sesiones = new HashMap<>();
    }

    // ============================================================
    // Login
    // ============================================================
    /**
     * Intenta autenticar a un usuario.
     * Acepta perfiles pro (rol 1+) y perfiles gratuitos (rol 0).
     *
     * Devuelve una Sesion nueva si las credenciales coinciden, o null
     * si no. Nunca revela si el nombre existe o no.
     */
    public Modelo.Sesion login(String nombre, String password, String ip) {
        if (nombre == null || nombre.isBlank()) return null;
        if (password == null || password.isEmpty()) return null;

        // 1. Buscar perfil pro en el índice
        Modelo.Perfil pro = null;
        try {
            pro = gestor.leerPerfil(nombre);
        } catch (Exception e) {
            // Ignorar: seguirá el flujo genérico
        }

        if (pro != null) {
            return verificarYAutenticarPro(pro, password, ip);
        }

        // 2. Buscar perfil gratis por nombre
        String idGratis = gestor.buscarIdGratuitoPorNombre(nombre);
        if (idGratis != null) {
            Modelo.PerfilGratuito gratis = null;
            try {
                gratis = gestor.leerPerfilGratuito(idGratis);
            } catch (Exception e) {
                // Ignorar
            }
            if (gratis != null) {
                return verificarYAutenticarGratuito(gratis, password, ip);
            }
        }

        // 3. No existe: hacer tiempo constante y devolver null
        hacerTiempoConstante(password);
        return null;
    }

    private Modelo.Sesion verificarYAutenticarPro(Modelo.Perfil pro, String password, String ip) {
        boolean ok = Cifrado.verificarPassword(password, pro.hashPassword(), pro.saltPassword());
        if (!ok) {
            pro.incrementarIntentosFallidos();
            try { gestor.actualizarPerfil(pro); } catch (Exception e) {}
            hacerTiempoConstante(password);
            return null;
        }
        if (!pro.estaActivo()) {
            return null;
        }
        pro.resetearIntentosFallidos();
        try { gestor.actualizarPerfil(pro); } catch (Exception e) {}
        return crearSesion(pro.id(), pro.rol());
    }

    private Modelo.Sesion verificarYAutenticarGratuito(
            Modelo.PerfilGratuito g, String password, String ip) {
        boolean ok = Cifrado.verificarPassword(password, g.hashPassword(), g.saltPassword());
        if (!ok) {
            hacerTiempoConstante(password);
            return null;
        }
        if (!g.estaActivo()) {
            return null;
        }
        return crearSesion(g.id(), Modelo.Rol.GRATUITO);
    }

    private void hacerTiempoConstante(String password) {
        // Hasheamos contra un salt ficticio para que el tiempo total
        // del login sea similar al de un login real.
        Cifrado.verificarPassword(password, HASH_FICTICIO, SALT_FICTICIO);
    }

    // ============================================================
    // Creación de perfil gratuito
    // ============================================================
    /**
     * Crea un perfil gratuito nuevo y devuelve una sesión ya iniciada.
     * Devuelve null si no se puede crear (nombre ocupado, límites, etc.).
     * No revela el motivo real: siempre devuelve el mismo error.
     */
    public Modelo.Sesion crearPerfilGratuito(String nombre, String password, String ip) {
        if (nombre == null || nombre.isBlank()) return null;
        if (password == null || password.isEmpty()) return null;

        // Si el nombre ya existe en pro o en gratis, no se puede.
        // Pero no lo revelamos: devolvemos null genérico.
        if (gestor.indice().contiene(nombre)) return null;
        if (gestor.existeNombreGratuito(nombre)) return null;

        String salt = Cifrado.generarSaltHex();
        String hash = Cifrado.hashearPassword(password, salt);

        Modelo.PerfilGratuito p;
        try {
            p = gestor.crearPerfilGratuito(nombre, hash, salt, ip);
        } catch (Exception e) {
            // Silencioso: no exponer razón.
            return null;
        }

        return crearSesion(p.id(), Modelo.Rol.GRATUITO);
    }

    // ============================================================
    // Logout y validación
    // ============================================================
    /**
     * Cierra la sesión asociada a un token.
     * Devuelve true si existía y se cerró, false si no existía.
     */
    public synchronized boolean logout(String token) {
        if (!esUuidValido(token)) return false;
        Modelo.Sesion s = sesiones.get(token);
        if (s == null) return false;
        s.cerrar();
        return true;
    }

    /**
     * Devuelve la sesión asociada a un token, o null si no es válida.
     * Detecta tokens modificados validando el formato UUID.
     */
    public synchronized Modelo.Sesion validar(String token) {
        if (!esUuidValido(token)) return null;
        Modelo.Sesion s = sesiones.get(token);
        if (s == null) return null;
        if (!s.activa()) return null;
        if (!s.estaVigente()) return null;
        return s;
    }

    /**
     * Devuelve true si el token tiene formato UUID v4 válido.
     * Cualquier otra cosa se considera modificación.
     */
    private static boolean esUuidValido(String token) {
        if (token == null || token.length() != 36) return false;
        try {
            UUID u = UUID.fromString(token);
            return u.toString().equalsIgnoreCase(token);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    // ============================================================
    // Sesiones
    // ============================================================
    private synchronized Modelo.Sesion crearSesion(String perfilId, Modelo.Rol rol) {
        // Contar sesiones activas de este perfil
        int activas = 0;
        for (Modelo.Sesion s : sesiones.values()) {
            if (s.perfilId().equals(perfilId) && s.activa() && s.estaVigente()) {
                activas++;
            }
        }
        if (activas >= MAX_SESIONES_POR_PERFIL) {
            return null;
        }

        // Crear sesión sin expiración automática (decisión D)
        Modelo.Sesion nueva = new Modelo.Sesion(
            UUID.randomUUID().toString(),
            perfilId,
            rol,
            System.currentTimeMillis(),
            Long.MAX_VALUE,   // expiración prácticamente infinita
            true
        );
        sesiones.put(nueva.token(), nueva);
        return nueva;
    }

    /**
     * Cierra todas las sesiones de un perfil. Útil cuando el admin
     * banea o elimina a un perfil.
     */
    public synchronized int cerrarTodasDe(String perfilId) {
        if (perfilId == null) return 0;
        int contador = 0;
        for (Modelo.Sesion s : sesiones.values()) {
            if (s.perfilId().equals(perfilId) && s.activa()) {
                s.cerrar();
                contador++;
            }
        }
        return contador;
    }

    /**
     * Devuelve todas las sesiones activas actualmente.
     * Solo para uso interno del admin.
     */
    public synchronized List<Modelo.Sesion> activas() {
        List<Modelo.Sesion> lista = new ArrayList<>();
        for (Modelo.Sesion s : sesiones.values()) {
            if (s.activa() && s.estaVigente()) lista.add(s);
        }
        return lista;
    }

    /**
     * Cuenta cuántas sesiones activas tiene un perfil.
     */
    public synchronized int contarSesionesDe(String perfilId) {
        if (perfilId == null) return 0;
        int contador = 0;
        for (Modelo.Sesion s : sesiones.values()) {
            if (s.perfilId().equals(perfilId) && s.activa() && s.estaVigente()) {
                contador++;
            }
        }
        return contador;
    }
}