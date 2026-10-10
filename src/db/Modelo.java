 
// Modelo.java
// Clases del dominio del sistema.
// Define qué es un Perfil, un PerfilGratuito, un Indice,
// un Baneado, una Sesion y un Rol.
// Conversión a/desde Json.
// Sin lógica de negocio: solo la forma de los datos.
// ============================================================
package db;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public final class Modelo {

    private Modelo() {} // no instanciable

    // ============================================================
    // Rol
    // ============================================================
    public enum Rol {
        GRATUITO(0, "GRATUITO"),
        PRO(1, "PRO"),
        EDITOR(2, "EDITOR"),
        NIVEL3(3, "NIVEL3"),
        ADMIN(4, "ADMIN");

        private final int nivel;
        private final String etiqueta;

        Rol(int nivel, String etiqueta) {
            this.nivel = nivel;
            this.etiqueta = etiqueta;
        }

        public int nivel() { return nivel; }
        public String etiqueta() { return etiqueta; }

        public boolean puedeVerOtrosPerfiles() {
            return nivel >= EDITOR.nivel;
        }

        public boolean puedeEditarSuPerfil() {
            return nivel >= NIVEL3.nivel;
        }

        public boolean esAdmin() {
            return this == ADMIN;
        }

        public boolean puedeAdministrar() {
            return this == ADMIN;
        }

        public static Rol desdeNombre(String s) {
            if (s == null) return null;
            for (Rol r : values()) {
                if (r.etiqueta.equals(s)) return r;
            }
            return null;
        }

        public static Rol desdeNivel(int n) {
            for (Rol r : values()) {
                if (r.nivel == n) return r;
            }
            return null;
        }
    }

    // ============================================================
    // Estado
    // ============================================================
    public enum Estado {
        ACTIVO, INACTIVO, BANEADO, ELIMINADO;

        public static Estado desdeNombre(String s) {
            if (s == null) return null;
            for (Estado e : values()) {
                if (e.name().equals(s)) return e;
            }
            return null;
        }
    }

    // ============================================================
    // Perfil (rol 1+, incluido admin)
    // Inmutable en lo esencial: id, nombre y claveInterna no cambian.
    // ============================================================
    public static final class Perfil {

        private final String id;              // UUID, inmutable
        private final String nombre;          // inmutable una vez creado
        private Rol rol;
        private String hashPassword;
        private String saltPassword;
        private Estado estado;
        private String ipCreacion;
        private final long fechaCreacion;
        private int intentosFallidos;
        private final String claveInterna;    // por perfil, inmutable

        private Perfil(
                String id, String nombre, Rol rol,
                String hashPassword, String saltPassword,
                Estado estado, String ipCreacion, long fechaCreacion,
                int intentosFallidos, String claveInterna) {
            this.id = id;
            this.nombre = nombre;
            this.rol = rol;
            this.hashPassword = hashPassword;
            this.saltPassword = saltPassword;
            this.estado = estado;
            this.ipCreacion = ipCreacion;
            this.fechaCreacion = fechaCreacion;
            this.intentosFallidos = intentosFallidos;
            this.claveInterna = claveInterna;
        }

        // Constructor para perfil nuevo
        public static Perfil nuevo(String nombre, Rol rol,
                                   String hashPassword, String saltPassword,
                                   String ipCreacion) {
            if (nombre == null || nombre.isBlank())
                throw new Json.JsonException("Nombre de perfil vacío");
            if (rol == null)
                throw new Json.JsonException("Rol nulo");
            if (rol == Rol.GRATUITO)
                throw new Json.JsonException("Use PerfilGratuito para rol 0");
            if (hashPassword == null || hashPassword.isBlank())
                throw new Json.JsonException("Hash de contraseña vacío");
            if (saltPassword == null || saltPassword.isBlank())
                throw new Json.JsonException("Salt de contraseña vacío");

            return new Perfil(
                UUID.randomUUID().toString(),
                nombre, rol,
                hashPassword, saltPassword,
                Estado.ACTIVO, ipCreacion,
                System.currentTimeMillis(),
                0,
                UUID.randomUUID().toString()
            );
        }

        // Getters
        public String id() { return id; }
        public String nombre() { return nombre; }
        public Rol rol() { return rol; }
        public String hashPassword() { return hashPassword; }
        public String saltPassword() { return saltPassword; }
        public Estado estado() { return estado; }
        public String ipCreacion() { return ipCreacion; }
        public long fechaCreacion() { return fechaCreacion; }
        public int intentosFallidos() { return intentosFallidos; }
        public String claveInterna() { return claveInterna; }

        public boolean estaActivo() { return estado == Estado.ACTIVO; }

        // Setters controlados
        public void setRol(Rol nuevoRol) {
            if (nuevoRol == null) throw new Json.JsonException("Rol nulo");
            if (nuevoRol == Rol.GRATUITO)
                throw new Json.JsonException("No se puede degradar a GRATUITO");
            this.rol = nuevoRol;
        }

        public void setEstado(Estado nuevo) {
            if (nuevo == null) throw new Json.JsonException("Estado nulo");
            this.estado = nuevo;
        }

       public void setIP(String nuevaIP) {
         if (nuevaIP == null || nuevaIP.isBlank())
            throw new Json.JsonException("IP vacía");
            this.ipCreacion= nuevaIP;		
}

        public void setHashPassword(String hash, String salt) {
            if (hash == null || hash.isBlank()) throw new Json.JsonException("Hash vacío");
            if (salt == null || salt.isBlank()) throw new Json.JsonException("Salt vacío");
            this.hashPassword = hash;
            this.saltPassword = salt;
        }

        public void incrementarIntentosFallidos() { this.intentosFallidos++; }
        public void resetearIntentosFallidos()    { this.intentosFallidos = 0; }

        // JSON
        public Json aJson() {
            Json j = Json.object();
            j.set("id", id);
            j.set("nombre", nombre);
            j.set("rol", rol.etiqueta());
            j.set("hashPassword", hashPassword);
            j.set("saltPassword", saltPassword);
            j.set("estado", estado.name());
            j.set("ipCreacion", ipCreacion);
            j.set("fechaCreacion", fechaCreacion);
            j.set("intentosFallidos", intentosFallidos);
            j.set("claveInterna", claveInterna);
            return j;
        }

        public static Perfil desdeJson(Json j) {
            String rolStr = j.get("rol").asString();
            Rol rol = Rol.desdeNombre(rolStr);
            if (rol == null) throw new Json.JsonException("Rol desconocido: " + rolStr);
            if (rol == Rol.GRATUITO) throw new Json.JsonException("Use PerfilGratuito para rol 0");

            String estadoStr = j.get("estado").asString();
            Estado estado = Estado.desdeNombre(estadoStr);
            if (estado == null) throw new Json.JsonException("Estado desconocido: " + estadoStr);

            return new Perfil(
                j.get("id").asString(),
                j.get("nombre").asString(),
                rol,
                j.get("hashPassword").asString(),
                j.get("saltPassword").asString(),
                estado,
                j.get("ipCreacion").asString(),
                j.get("fechaCreacion").asLong(),
                (int) j.get("intentosFallidos").asLong(),
                j.get("claveInterna").asString()
            );
        }

        // toString seguro: NO filtra contraseñas
        @Override
        public String toString() {
            return "Perfil{id=" + id + ", nombre=" + nombre + ", rol=" + rol + ", estado=" + estado + "}";
        }
    }

    // ============================================================
    // PerfilGratuito (rol 0)
    // Más liviano que Perfil. Guarda actividad.
    // ============================================================
    public static final class PerfilGratuito {

        public static final int USOS_INICIALES = 5;

        private final String id;
        private final String nombre;
        private String hashPassword;
        private String saltPassword;
        private final String ipCreacion;
        private final long fechaCreacion;
        private int usosRestantes;
        private Estado estado;
        private final List<String> actividad;
        private final String claveInterna;    // NUEVO: para cifrar el archivo

        private PerfilGratuito(
                String id, String nombre,
                String hashPassword, String saltPassword,
                String ipCreacion, long fechaCreacion,
                int usosRestantes, Estado estado,
                List<String> actividad,
                String claveInterna) {
            this.id = id;
            this.nombre = nombre;
            this.hashPassword = hashPassword;
            this.saltPassword = saltPassword;
            this.ipCreacion = ipCreacion;
            this.fechaCreacion = fechaCreacion;
            this.usosRestantes = usosRestantes;
            this.estado = estado;
            this.actividad = actividad != null ? actividad : new ArrayList<>();
            this.claveInterna = claveInterna;
        }

        public static PerfilGratuito nuevo(String nombre,
                                           String hashPassword, String saltPassword,
                                           String ipCreacion) {
            if (nombre == null || nombre.isBlank())
                throw new Json.JsonException("Nombre de perfil vacío");
            if (hashPassword == null || hashPassword.isBlank())
                throw new Json.JsonException("Hash de contraseña vacío");
            if (saltPassword == null || saltPassword.isBlank())
                throw new Json.JsonException("Salt de contraseña vacío");

            return new PerfilGratuito(
                UUID.randomUUID().toString(),
                nombre, hashPassword, saltPassword,
                ipCreacion, System.currentTimeMillis(),
                USOS_INICIALES, Estado.ACTIVO,
                new ArrayList<>(),
                UUID.randomUUID().toString()
            );
        }

        public String id() { return id; }
        public String nombre() { return nombre; }
        public String hashPassword() { return hashPassword; }
        public String saltPassword() { return saltPassword; }
        public String ipCreacion() { return ipCreacion; }
        public long fechaCreacion() { return fechaCreacion; }
        public int usosRestantes() { return usosRestantes; }
        public Estado estado() { return estado; }
        public List<String> actividad() { return new ArrayList<>(actividad); }
        public String claveInterna() { return claveInterna; }  // NUEVO

        public boolean estaActivo() {
            return estado == Estado.ACTIVO && usosRestantes > 0;
        }

        public boolean puedeUsar() { return estaActivo(); }

        public void consumirUso(String descripcion) {
            if (usosRestantes <= 0) throw new Json.JsonException("Sin usos restantes");
            usosRestantes--;
            actividad.add(System.currentTimeMillis() + "|" + (descripcion == null ? "" : descripcion));
            if (usosRestantes == 0) estado = Estado.INACTIVO;
        }

        public void setEstado(Estado nuevo) {
            if (nuevo == null) throw new Json.JsonException("Estado nulo");
            this.estado = nuevo;
        }

        public void setHashPassword(String hash, String salt) {
            if (hash == null || hash.isBlank()) throw new Json.JsonException("Hash vacío");
            if (salt == null || salt.isBlank()) throw new Json.JsonException("Salt vacío");
            this.hashPassword = hash;
            this.saltPassword = salt;
        }

        public Json aJson() {
            Json j = Json.object();
            j.set("id", id);
            j.set("nombre", nombre);
            j.set("hashPassword", hashPassword);
            j.set("saltPassword", saltPassword);
            j.set("ipCreacion", ipCreacion);
            j.set("fechaCreacion", fechaCreacion);
            j.set("usosRestantes", usosRestantes);
            j.set("estado", estado.name());
            j.set("claveInterna", claveInterna);   // NUEVO
            Json arr = Json.array();
            for (String a : actividad) arr.add(a);
            j.set("actividad", arr);
            return j;
        }

        public static PerfilGratuito desdeJson(Json j) {
            String estadoStr = j.get("estado").asString();
            Estado estado = Estado.desdeNombre(estadoStr);
            if (estado == null) throw new Json.JsonException("Estado desconocido: " + estadoStr);

            List<String> act = new ArrayList<>();
            Json arr = j.get("actividad");
            if (arr != null && arr.esArray()) {
                for (Json e : arr.elementos()) act.add(e.asString());
            }

            return new PerfilGratuito(
                j.get("id").asString(),
                j.get("nombre").asString(),
                j.get("hashPassword").asString(),
                j.get("saltPassword").asString(),
                j.get("ipCreacion").asString(),
                j.get("fechaCreacion").asLong(),
                (int) j.get("usosRestantes").asLong(),
                estado,
                act,
                j.get("claveInterna").asString()   // NUEVO
            );
        }

        @Override
        public String toString() {
            return "PerfilGratuito{id=" + id + ", nombre=" + nombre
                + ", usosRestantes=" + usosRestantes + ", estado=" + estado + "}";
        }
    }

    // ============================================================
    // Entrada liviana del índice.
    // Guarda la claveInterna del perfil para poder descifrarlo
    // sin necesidad de leer primero el archivo cifrado.
    // ============================================================
    public static final class EntradaIndice {
        private final String nombre;
        private final Rol rol;
        private final String ruta;
        private final Estado estado;
        private final String claveInterna;   // NUEVO

        public EntradaIndice(String nombre, Rol rol, String ruta, Estado estado,
                             String claveInterna) {
            if (nombre == null || nombre.isBlank()) throw new Json.JsonException("Nombre vacío");
            if (rol == null) throw new Json.JsonException("Rol nulo");
            if (ruta == null || ruta.isBlank()) throw new Json.JsonException("Ruta vacía");
            if (estado == null) throw new Json.JsonException("Estado nulo");
            if (claveInterna == null || claveInterna.isBlank())
                throw new Json.JsonException("Clave interna vacía");
            this.nombre = nombre;
            this.rol = rol;
            this.ruta = ruta;
            this.estado = estado;
            this.claveInterna = claveInterna;
        }

        public String nombre() { return nombre; }
        public Rol rol() { return rol; }
        public String ruta() { return ruta; }
        public Estado estado() { return estado; }
        public String claveInterna() { return claveInterna; }   // NUEVO

        public Json aJson() {
            Json j = Json.object();
            j.set("nombre", nombre);
            j.set("rol", rol.etiqueta());
            j.set("ruta", ruta);
            j.set("estado", estado.name());
            j.set("claveInterna", claveInterna);   // NUEVO
            return j;
        }

        public static EntradaIndice desdeJson(Json j) {
            Rol rol = Rol.desdeNombre(j.get("rol").asString());
            if (rol == null) throw new Json.JsonException("Rol desconocido");
            Estado estado = Estado.desdeNombre(j.get("estado").asString());
            if (estado == null) throw new Json.JsonException("Estado desconocido");
            return new EntradaIndice(
                j.get("nombre").asString(),
                rol,
                j.get("ruta").asString(),
                estado,
                j.get("claveInterna").asString()   // NUEVO
            );
        }

        @Override
        public String toString() {
            return "EntradaIndice{nombre=" + nombre + ", rol=" + rol
                + ", estado=" + estado + "}";
        }
    }

    // ============================================================
    // Indice
    // Lista liviana de perfiles rol 1+.
    // Los rol 0 van aparte.
    // ============================================================
    public static final class Indice {

        public static final int VERSION_ACTUAL = 1;
        public static final int LIMITE_ROL0_DEFECTO = 2000;

        private int version;
        private int limiteRol0;
        private final List<EntradaIndice> entradas;
        private String checksum; // se calcula al guardar

        public Indice() {
            this(VERSION_ACTUAL, LIMITE_ROL0_DEFECTO, new ArrayList<>(), null);
        }

        private Indice(int version, int limiteRol0,
                       List<EntradaIndice> entradas, String checksum) {
            this.version = version;
            this.limiteRol0 = limiteRol0;
            this.entradas = entradas != null ? entradas : new ArrayList<>();
            this.checksum = checksum;
        }

        public int version() { return version; }
        public int limiteRol0() { return limiteRol0; }
        public List<EntradaIndice> entradas() { return new ArrayList<>(entradas); }
        public String checksum() { return checksum; }

        public void setLimiteRol0(int limite) {
            if (limite < 0) throw new Json.JsonException("Límite negativo");
            this.limiteRol0 = limite;
        }

        public void setChecksum(String c) { this.checksum = c; }

        public void agregar(EntradaIndice e) {
            if (e == null) throw new Json.JsonException("Entrada nula");
            for (EntradaIndice x : entradas) {
                if (x.nombre().equals(e.nombre()))
                    throw new Json.JsonException("Nombre ya en el índice: " + e.nombre());
            }
            entradas.add(e);
        }

        public boolean contiene(String nombre) {
            if (nombre == null) return false;
            for (EntradaIndice x : entradas) {
                if (x.nombre().equals(nombre)) return true;
            }
            return false;
        }

        public EntradaIndice buscar(String nombre) {
            if (nombre == null) return null;
            for (EntradaIndice x : entradas) {
                if (x.nombre().equals(nombre)) return x;
            }
            return null;
        }

        public void quitar(String nombre) {
            entradas.removeIf(x -> x.nombre().equals(nombre));
        }

        public Json aJson() {
            Json j = Json.object();
            j.set("version", version);
            j.set("limiteRol0", limiteRol0);
            Json arr = Json.array();
            for (EntradaIndice e : entradas) arr.add(e.aJson());
            j.set("perfiles", arr);
            if (checksum != null) j.set("checksum", checksum);
            return j;
        }

        public static Indice desdeJson(Json j) {
            int version = (int) j.get("version").asLong();
            int limite = (int) j.get("limiteRol0").asLong();

            List<EntradaIndice> lista = new ArrayList<>();
            Json arr = j.get("perfiles");
            if (arr != null && arr.esArray()) {
                for (Json e : arr.elementos()) {
                    lista.add(EntradaIndice.desdeJson(e));
                }
            }

            String checksum = null;
            Json c = j.get("checksum");
            if (c != null && c.esString()) checksum = c.asString();

            return new Indice(version, limite, lista, checksum);
        }

        @Override
        public String toString() {
            return "Indice{version=" + version + ", limiteRol0=" + limiteRol0
                + ", perfiles=" + entradas.size() + "}";
        }
    }

    // ============================================================
    // Baneado
    // ============================================================
    public static final class Baneado {
        private final String id;
        private final String ip;
        private final String motivo;
        private final long fecha;

        public Baneado(String id, String ip, String motivo, long fecha) {
            if (id == null || id.isBlank()) throw new Json.JsonException("ID vacío");
            this.id = id;
            this.ip = ip;
            this.motivo = motivo != null ? motivo : "";
            this.fecha = fecha;
        }

        public static Baneado nuevo(String id, String ip, String motivo) {
            return new Baneado(id, ip, motivo, System.currentTimeMillis());
        }

        public String id() { return id; }
        public String ip() { return ip; }
        public String motivo() { return motivo; }
        public long fecha() { return fecha; }

        public Json aJson() {
            Json j = Json.object();
            j.set("id", id);
            j.set("ip", ip);
            j.set("motivo", motivo);
            j.set("fecha", fecha);
            return j;
        }

        public static Baneado desdeJson(Json j) {
            return new Baneado(
                j.get("id").asString(),
                j.get("ip").asString(),
                j.get("motivo").asString(),
                j.get("fecha").asLong()
            );
        }

        @Override
        public String toString() {
            return "Baneado{id=" + id + ", ip=" + ip + "}";
        }
    }

    // ============================================================
    // Sesion
    // ============================================================
    public static final class Sesion {
        private final String token;
        private final String perfilId;
        private final Rol rol;
        private final long fechaInicio;
        private long fechaExpiracion;
        private boolean activa;

        public Sesion(String token, String perfilId, Rol rol,
                      long fechaInicio, long fechaExpiracion, boolean activa) {
            if (token == null || token.isBlank()) throw new Json.JsonException("Token vacío");
            if (perfilId == null || perfilId.isBlank()) throw new Json.JsonException("PerfilId vacío");
            if (rol == null) throw new Json.JsonException("Rol nulo");
            this.token = token;
            this.perfilId = perfilId;
            this.rol = rol;
            this.fechaInicio = fechaInicio;
            this.fechaExpiracion = fechaExpiracion;
            this.activa = activa;
        }

        public static Sesion nueva(String perfilId, Rol rol, long duracionMs) {
            long ahora = System.currentTimeMillis();
            return new Sesion(
                UUID.randomUUID().toString(),
                perfilId, rol,
                ahora, ahora + duracionMs,
                true
            );
        }

        public String token() { return token; }
        public String perfilId() { return perfilId; }
        public Rol rol() { return rol; }
        public long fechaInicio() { return fechaInicio; }
        public long fechaExpiracion() { return fechaExpiracion; }
        public boolean activa() { return activa; }

        public boolean estaVigente() {
            return activa && System.currentTimeMillis() < fechaExpiracion;
        }

        public void cerrar() { this.activa = false; }

        public Json aJson() {
            Json j = Json.object();
            j.set("token", token);
            j.set("perfilId", perfilId);
            j.set("rol", rol.etiqueta());
            j.set("fechaInicio", fechaInicio);
            j.set("fechaExpiracion", fechaExpiracion);
            j.set("activa", activa);
            return j;
        }

        public static Sesion desdeJson(Json j) {
            Rol rol = Rol.desdeNombre(j.get("rol").asString());
            if (rol == null) throw new Json.JsonException("Rol desconocido");
            return new Sesion(
                j.get("token").asString(),
                j.get("perfilId").asString(),
                rol,
                j.get("fechaInicio").asLong(),
                j.get("fechaExpiracion").asLong(),
                j.get("activa").asBoolean()
            );
        }

        @Override
        public String toString() {
            return "Sesion{perfilId=" + perfilId + ", rol=" + rol
                + ", activa=" + activa + "}";
        }
    }

    // ============================================================
    // Admin por defecto
    // El servidor lo usa al primer arranque.
    // ============================================================
    public static final class AdminPorDefecto {
        public static final String NOMBRE_DEFECTO = "admin";

        private AdminPorDefecto() {}

        public static Perfil crear(String nombre, String hashPassword, String saltPassword) {
            if (nombre == null || nombre.isBlank()) nombre = NOMBRE_DEFECTO;
            return Perfil.nuevo(nombre, Rol.ADMIN, hashPassword, saltPassword, "127.0.0.1");
        }
    }
}