// ============================================================
// Cifrado.java
// Hasheo de contraseñas, cifrado de perfiles y gestión de la
// clave maestra del servidor.
//
// - Hasheo: PBKDF2 + SHA-256, 200.000 iteraciones, salt 32 bytes.
// - Verificación: en tiempo constante.
// - Cifrado de perfiles: AES-GCM, clave derivada por perfil,
//   ID como AAD.
// - Clave maestra: cifrada en disco con contraseña; la contraseña
//   vive en un archivo con permisos restrictivos.
// - Contador de reinicios: cada 30, se pide la contraseña.
// - Rotación de clave maestra.
//
// Depende solo del JDK. Sin dependencias externas.
// ============================================================
package db;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class Cifrado {

    // ============================================================
    // Constantes
    // ============================================================
    private static final String PBKDF2_ALGORITMO = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITERACIONES = 200_000;
    private static final int PBKDF2_LONGITUD_CLAVE = 256; // bits

    private static final String AES_ALGORITMO = "AES";
    private static final String AES_MODO = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int SALT_BYTES = 32;

    private static final int REINICIOS_PARA_PEDIR_CLAVE = 30;

    private static final Path DIR_DATA              = Paths.get("server", "data");
    private static final Path DIR_SERVER            = Paths.get("server");
    private static final Path CLAVE_MAESTRA_ENC     = DIR_SERVER.resolve("clave_maestra.enc");
    private static final Path CLAVE_MAESTRA_PWD     = DIR_SERVER.resolve("clave_maestra.pwd");
    private static final Path ESTADO_SERVIDOR_JSON  = DIR_DATA.resolve("estado_servidor.json");

    private static final SecureRandom RANDOM = new SecureRandom();

    // Clave maestra en memoria (solo mientras el proceso vive)
    private static byte[] claveMaestraEnMemoria = null;

    private Cifrado() {} // no instanciable

    // ============================================================
    // Clave maestra: inicialización y carga
    // ============================================================
    /**
     * Arranca el sistema de cifrado.
     * - Incrementa el contador de reinicios.
     * - Si toca pedir la contraseña, la pide por consola.
     * - Si no, lee la contraseña del archivo .pwd.
     * - Descifra la clave maestra y la deja en memoria.
     *
     * @param forzarPassword si true, siempre pide la contraseña.
     */
    public static synchronized void arrancar(boolean forzarPassword) {
        asegurarCarpetas();

        int reinicios = incrementarContadorReinicios();
        boolean pedir = forzarPassword || (reinicios % REINICIOS_PARA_PEDIR_CLAVE == 0);

        byte[] passwordBytes;

        if (!Files.exists(CLAVE_MAESTRA_ENC)) {
            // Primer arranque: crear clave maestra desde cero
            System.out.println("[cifrado] primer arranque: definí la contraseña maestra.");
            passwordBytes = pedirPasswordPorConsola(true);
            crearClaveMaestraInicial(passwordBytes);
            borrarDeMemoria(passwordBytes);
            return;
        }

        if (pedir) {
            System.out.println("[cifrado] reinicio #" + reinicios
                + " — toca verificación de contraseña maestra.");
            passwordBytes = pedirPasswordPorConsola(false);
        } else {
            passwordBytes = leerPasswordDeArchivo();
        }

        try {
            claveMaestraEnMemoria = descifrarClaveMaestra(passwordBytes);
        } finally {
            borrarDeMemoria(passwordBytes);
        }

        System.out.println("[cifrado] clave maestra cargada (reinicio #" + reinicios + ").");
    }

    /**
     * Devuelve la clave maestra en memoria.
     * Falla si no fue cargada antes.
     */
    public static synchronized byte[] claveMaestra() {
        if (claveMaestraEnMemoria == null) {
            throw new Json.JsonException("Clave maestra no cargada. Llamá a Cifrado.arrancar() primero.");
        }
        return Arrays.copyOf(claveMaestraEnMemoria, claveMaestraEnMemoria.length);
    }

    // ============================================================
    // Creación de la clave maestra inicial
    // ============================================================
    private static void crearClaveMaestraInicial(byte[] passwordBytes) {
        byte[] clave = new byte[32];
        RANDOM.nextBytes(clave);

        guardarClaveMaestraCifrada(clave, passwordBytes);
        guardarPasswordEnArchivo(passwordBytes);

        claveMaestraEnMemoria = Arrays.copyOf(clave, clave.length);
        borrarDeMemoria(clave);

        System.out.println("[cifrado] clave maestra creada.");
        System.out.println("[cifrado] IMPORTANTE: respaldá " + CLAVE_MAESTRA_ENC
            + " y " + CLAVE_MAESTRA_PWD + " en un lugar seguro.");
    }

    // ============================================================
    // Cifrado / descifrado de la clave maestra
    // ============================================================
    private static void guardarClaveMaestraCifrada(byte[] clave, byte[] passwordBytes) {
        try {
            byte[] salt = generarSalt();
            byte[] nonce = generarNonce();

            SecretKey key = derivarClaveDePassword(passwordBytes, salt);
            byte[] cifrado = aesGcmCifrar(clave, key, nonce, null);

            byte[] salida = new byte[salt.length + nonce.length + cifrado.length];
            System.arraycopy(salt, 0, salida, 0, salt.length);
            System.arraycopy(nonce, 0, salida, salt.length, nonce.length);
            System.arraycopy(cifrado, 0, salida, salt.length + nonce.length, cifrado.length);

            Files.write(CLAVE_MAESTRA_ENC, salida);
        } catch (IOException e) {
            throw new Json.JsonException("Error guardando clave maestra: " + e.getMessage());
        }
    }

    private static byte[] descifrarClaveMaestra(byte[] passwordBytes) {
        try {
            byte[] bruto = Files.readAllBytes(CLAVE_MAESTRA_ENC);
            if (bruto.length < SALT_BYTES + GCM_NONCE_BYTES + GCM_TAG_BITS / 8) {
                throw new Json.JsonException("Archivo clave_maestra.enc corrupto o incompleto.");
            }

            byte[] salt = Arrays.copyOfRange(bruto, 0, SALT_BYTES);
            byte[] nonce = Arrays.copyOfRange(bruto, SALT_BYTES, SALT_BYTES + GCM_NONCE_BYTES);
            byte[] cifrado = Arrays.copyOfRange(bruto, SALT_BYTES + GCM_NONCE_BYTES, bruto.length);

            SecretKey key = derivarClaveDePassword(passwordBytes, salt);
            return aesGcmDescifrar(cifrado, key, nonce, null);
        } catch (IOException e) {
            throw new Json.JsonException("Error leyendo clave maestra: " + e.getMessage());
        }
    }

    // ============================================================
    // Archivo .pwd
    // ============================================================
    private static void guardarPasswordEnArchivo(byte[] passwordBytes) {
        try {
            Files.write(CLAVE_MAESTRA_PWD, passwordBytes);
            aplicarPermisosRestrictivos(CLAVE_MAESTRA_PWD);
        } catch (IOException e) {
            throw new Json.JsonException("Error guardando .pwd: " + e.getMessage());
        }
    }

    private static byte[] leerPasswordDeArchivo() {
        if (!Files.exists(CLAVE_MAESTRA_PWD)) {
            System.out.println("[cifrado] no existe " + CLAVE_MAESTRA_PWD
                + ". Ingresá la contraseña maestra:");
            return pedirPasswordPorConsola(false);
        }
        try {
            return Files.readAllBytes(CLAVE_MAESTRA_PWD);
        } catch (IOException e) {
            throw new Json.JsonException("Error leyendo .pwd: " + e.getMessage());
        }
    }

    private static void aplicarPermisosRestrictivos(Path ruta) {
        try {
            Set<PosixFilePermission> permisos = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(ruta, permisos);
        } catch (UnsupportedOperationException e) {
            // Windows: no hay POSIX. Ignorar.
        } catch (IOException e) {
            System.err.println("[cifrado] no se pudieron aplicar permisos a " + ruta
                + ": " + e.getMessage());
        }
    }

    // ============================================================
    // Lectura por consola
    // ============================================================
    private static byte[] pedirPasswordPorConsola(boolean confirmar) {
        Console consola = System.console();
        if (consola != null) {
            char[] p1 = consola.readPassword("Contraseña maestra: ");
            if (confirmar) {
                char[] p2 = consola.readPassword("Confirmá la contraseña: ");
                if (!Arrays.equals(p1, p2)) {
                    Arrays.fill(p1, '\0');
                    Arrays.fill(p2, '\0');
                    throw new Json.JsonException("Las contraseñas no coinciden.");
                }
                Arrays.fill(p2, '\0');
            }
            byte[] bytes = new String(p1).getBytes(StandardCharsets.UTF_8);
            Arrays.fill(p1, '\0');
            return bytes;
        }
        // Fallback para entornos sin consola interactiva
        System.out.print("Contraseña maestra: ");
        try {
            byte[] buf = new byte[256];
            int n = System.in.read(buf);
            if (n <= 0) throw new Json.JsonException("Contraseña vacía.");
            int fin = n;
            while (fin > 0 && (buf[fin - 1] == '\n' || buf[fin - 1] == '\r')) fin--;
            return Arrays.copyOf(buf, fin);
        } catch (IOException e) {
            throw new Json.JsonException("Error leyendo contraseña: " + e.getMessage());
        }
    }

    // ============================================================
    // Hasheo de contraseñas de usuario
    // ============================================================
    /**
     * Devuelve el hash de una contraseña.
     * Formato: hex de 32 bytes.
     */
    public static String hashearPassword(String password, String saltHex) {
        if (password == null) throw new Json.JsonException("Password nulo");
        if (saltHex == null) throw new Json.JsonException("Salt nulo");

        byte[] salt = hexABytes(saltHex);
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

        try {
            PBEKeySpec spec = new PBEKeySpec(
                new String(passwordBytes, StandardCharsets.UTF_8).toCharArray(),
                salt, PBKDF2_ITERACIONES, PBKDF2_LONGITUD_CLAVE
            );
            SecretKeyFactory fab = SecretKeyFactory.getInstance(PBKDF2_ALGORITMO);
            byte[] hash = fab.generateSecret(spec).getEncoded();
            return bytesAHex(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new Json.JsonException("Error hasheando: " + e.getMessage());
        } finally {
            borrarDeMemoria(passwordBytes);
        }
    }

    /**
     * Verifica una contraseña contra un hash guardado.
     * Comparación en tiempo constante.
     */
    public static boolean verificarPassword(String password, String hashHex, String saltHex) {
        if (password == null || hashHex == null || saltHex == null) return false;
        String calculado = hashearPassword(password, saltHex);
        return comparacionTiempoConstante(calculado, hashHex);
    }

    private static boolean comparacionTiempoConstante(String a, String b) {
        if (a == null || b == null) return false;
        byte[] ba = a.getBytes(StandardCharsets.UTF_8);
        byte[] bb = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(ba, bb);
    }

    // ============================================================
    // Cifrado de perfiles (AES-GCM por perfil)
    // ============================================================
    /**
     * Cifra los bytes de un perfil.
     * La clave se deriva de claveInterna + claveMaestra.
     * El ID del perfil se usa como AAD.
     */
    public static byte[] cifrarPerfil(byte[] contenido, String claveInternaHex, String idPerfil) {
        if (contenido == null) throw new Json.JsonException("Contenido nulo");
        if (claveInternaHex == null) throw new Json.JsonException("Clave interna nula");
        if (idPerfil == null) throw new Json.JsonException("ID de perfil nulo");

        byte[] key = derivarClaveDePerfil(claveInternaHex);
        byte[] nonce = generarNonce();
        byte[] aad = idPerfil.getBytes(StandardCharsets.UTF_8);

        try {
            byte[] cifrado = aesGcmCifrar(contenido, new SecretKeySpec(key, AES_ALGORITMO), nonce, aad);
            byte[] salida = new byte[nonce.length + cifrado.length];
            System.arraycopy(nonce, 0, salida, 0, nonce.length);
            System.arraycopy(cifrado, 0, salida, nonce.length, cifrado.length);
            return salida;
        } finally {
            borrarDeMemoria(key);
        }
    }

    /**
     * Descifra los bytes de un perfil.
     */
    public static byte[] descifrarPerfil(byte[] cifrado, String claveInternaHex, String idPerfil) {
        if (cifrado == null) throw new Json.JsonException("Cifrado nulo");
        if (claveInternaHex == null) throw new Json.JsonException("Clave interna nula");
        if (idPerfil == null) throw new Json.JsonException("ID de perfil nulo");
        if (cifrado.length < GCM_NONCE_BYTES + GCM_TAG_BITS / 8) {
            throw new Json.JsonException("Cifrado demasiado corto.");
        }

        byte[] nonce = Arrays.copyOfRange(cifrado, 0, GCM_NONCE_BYTES);
        byte[] cuerpo = Arrays.copyOfRange(cifrado, GCM_NONCE_BYTES, cifrado.length);

        byte[] key = derivarClaveDePerfil(claveInternaHex);
        byte[] aad = idPerfil.getBytes(StandardCharsets.UTF_8);

        try {
            return aesGcmDescifrar(cuerpo, new SecretKeySpec(key, AES_ALGORITMO), nonce, aad);
        } catch (Json.JsonException e) {
            throw new Json.JsonException("No se pudo descifrar el perfil (¿clave o ID incorrectos?).");
        } finally {
            borrarDeMemoria(key);
        }
    }

    private static byte[] derivarClaveDePerfil(String claveInternaHex) {
        byte[] claveInterna = hexABytes(claveInternaHex);
        byte[] maestra = claveMaestra();
        byte[] combinada = new byte[claveInterna.length + maestra.length];
        System.arraycopy(claveInterna, 0, combinada, 0, claveInterna.length);
        System.arraycopy(maestra, 0, combinada, claveInterna.length, maestra.length);

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(combinada);
            borrarDeMemoria(combinada);
            borrarDeMemoria(claveInterna);
            borrarDeMemoria(maestra);
            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new Json.JsonException("SHA-256 no disponible.");
        }
    }

    // ============================================================
    // AES-GCM de bajo nivel
    // ============================================================
    private static byte[] aesGcmCifrar(byte[] datos, SecretKey key, byte[] nonce, byte[] aad) {
        try {
            Cipher c = Cipher.getInstance(AES_MODO);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            c.init(Cipher.ENCRYPT_MODE, key, spec);
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(datos);
        } catch (Exception e) {
            throw new Json.JsonException("Error cifrando: " + e.getMessage());
        }
    }

    private static byte[] aesGcmDescifrar(byte[] datos, SecretKey key, byte[] nonce, byte[] aad) {
        try {
            Cipher c = Cipher.getInstance(AES_MODO);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            c.init(Cipher.DECRYPT_MODE, key, spec);
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(datos);
        } catch (Exception e) {
            throw new Json.JsonException("Error descifrando: " + e.getMessage());
        }
    }

    private static SecretKey derivarClaveDePassword(byte[] passwordBytes, byte[] salt) {
        try {
            char[] pw = new String(passwordBytes, StandardCharsets.UTF_8).toCharArray();
            PBEKeySpec spec = new PBEKeySpec(pw, salt, PBKDF2_ITERACIONES, PBKDF2_LONGITUD_CLAVE);
            SecretKeyFactory fab = SecretKeyFactory.getInstance(PBKDF2_ALGORITMO);
            byte[] keyBytes = fab.generateSecret(spec).getEncoded();
            Arrays.fill(pw, '\0');
            return new SecretKeySpec(keyBytes, AES_ALGORITMO);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new Json.JsonException("Error derivando clave: " + e.getMessage());
        }
    }

    // ============================================================
    // Contador de reinicios
    // ============================================================
    private static int incrementarContadorReinicios() {
        Json estado = cargarEstadoServidor();
        int actual = (int) estado.get("reinicios").asLong(0);
        int nuevo = actual + 1;
        estado.set("reinicios", nuevo);
        estado.set("version", 1);
        guardarEstadoServidor(estado);
        return nuevo;
    }

    private static Json cargarEstadoServidor() {
        if (!Files.exists(ESTADO_SERVIDOR_JSON)) {
            Json j = Json.object();
            j.set("reinicios", 0);
            j.set("ultimaRotacion", 0);
            j.set("version", 1);
            return j;
        }
        try {
            String texto = new String(Files.readAllBytes(ESTADO_SERVIDOR_JSON), StandardCharsets.UTF_8);
            return Json.parse(texto);
        } catch (Exception e) {
            System.err.println("[cifrado] estado_servidor.json corrupto: " + e.getMessage());
            Json j = Json.object();
            j.set("reinicios", 0);
            j.set("ultimaRotacion", 0);
            j.set("version", 1);
            return j;
        }
    }

    private static void guardarEstadoServidor(Json estado) {
        try {
            Files.write(ESTADO_SERVIDOR_JSON,
                estado.toString(2).getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new Json.JsonException("Error guardando estado del servidor: " + e.getMessage());
        }
    }

    public static synchronized int reiniciosActuales() {
        return (int) cargarEstadoServidor().get("reinicios").asLong(0);
    }

// ============================================================
// Derivación de clave interna (sin guardarla en ningún lado)
// ============================================================
/**
 * Deriva la clave interna de un perfil a partir de su ID
 * y la clave maestra del servidor.
 *
 * Se calcula al vuelo cada vez que se necesita. No se guarda
 * en ningún archivo, ni en el nombre, ni en el índice, ni en el
 * propio perfil. Solo vive en memoria mientras se usa.
 *
 * Devuelve el hash SHA-256 en hex (64 caracteres).
 */
public static String derivarClaveInterna(String id) {
    if (id == null || id.isBlank())
        throw new Json.JsonException("ID nulo o vacío");

    byte[] maestra = claveMaestra();
    byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
    byte[] combinado = new byte[idBytes.length + maestra.length];
    System.arraycopy(idBytes, 0, combinado, 0, idBytes.length);
    System.arraycopy(maestra, 0, combinado, idBytes.length, maestra.length);

    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(combinado);
        return bytesAHex(hash);
    } catch (NoSuchAlgorithmException e) {
        throw new Json.JsonException("SHA-256 no disponible");
    } finally {
        borrarDeMemoria(combinado);
        borrarDeMemoria(idBytes);
        borrarDeMemoria(maestra);
    }
}


    // ============================================================
    // Rotación de clave maestra
    // ============================================================
    /**
     * Rota la clave maestra.
     * Recibe la lista de archivos de perfil a re-cifrar y sus IDs.
     * Devuelve cuántos se re-cifraron.
     *
     * @param passwordActual  contraseña actual del .enc
     * @param passwordNueva   contraseña nueva
     * @param perfiles        lista de (rutaArchivo, claveInternaHex, idPerfil)
     */
    public static synchronized int rotarClaveMaestra(
            byte[] passwordActual,
            byte[] passwordNueva,
            List<PerfilParaRotar> perfiles) {

        byte[] claveVieja = descifrarClaveMaestra(passwordActual);
        byte[] claveNueva = new byte[32];
        RANDOM.nextBytes(claveNueva);

        int contador = 0;
        List<byte[]> contenidosDescifrados = new ArrayList<>();
        List<PerfilParaRotar> procesados = new ArrayList<>();

        try {
            // 1. Descifrar todo con la clave vieja (en memoria)
            claveMaestraEnMemoria = claveVieja;
            for (PerfilParaRotar p : perfiles) {
                byte[] cifrado = Files.readAllBytes(p.ruta);
                byte[] plano = descifrarPerfil(cifrado, p.claveInternaHex, p.idPerfil);
                contenidosDescifrados.add(plano);
                procesados.add(p);
            }

            // 2. Cambiar a la clave nueva
            claveMaestraEnMemoria = claveNueva;

            // 3. Re-cifrar todo
            for (int i = 0; i < procesados.size(); i++) {
                PerfilParaRotar p = procesados.get(i);
                byte[] nuevoCifrado = cifrarPerfil(
                    contenidosDescifrados.get(i),
                    p.claveInternaHex,
                    p.idPerfil
                );
                Files.write(p.ruta, nuevoCifrado);
                contador++;
            }

            // 4. Guardar la nueva clave cifrada
            guardarClaveMaestraCifrada(claveNueva, passwordNueva);
            guardarPasswordEnArchivo(passwordNueva);

            // 5. Actualizar estado
            Json estado = cargarEstadoServidor();
            estado.set("ultimaRotacion", System.currentTimeMillis());
            guardarEstadoServidor(estado);

            return contador;
        } catch (IOException e) {
            throw new Json.JsonException("Error durante la rotación: " + e.getMessage());
        } finally {
            borrarDeMemoria(claveVieja);
            borrarDeMemoria(claveNueva);
            for (byte[] c : contenidosDescifrados) borrarDeMemoria(c);
        }
    }

    public static final class PerfilParaRotar {
        public final Path ruta;
        public final String claveInternaHex;
        public final String idPerfil;

        public PerfilParaRotar(Path ruta, String claveInternaHex, String idPerfil) {
            this.ruta = ruta;
            this.claveInternaHex = claveInternaHex;
            this.idPerfil = idPerfil;
        }
    }

    // ============================================================
    // Utilidades
    // ============================================================
    public static byte[] generarSalt() {
        byte[] b = new byte[SALT_BYTES];
        RANDOM.nextBytes(b);
        return b;
    }

    public static String generarSaltHex() {
        return bytesAHex(generarSalt());
    }

    public static byte[] generarNonce() {
        byte[] b = new byte[GCM_NONCE_BYTES];
        RANDOM.nextBytes(b);
        return b;
    }

    public static String bytesAHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] hexABytes(String hex) {
        if (hex == null) throw new Json.JsonException("Hex nulo");
        if (hex.length() % 2 != 0) throw new Json.JsonException("Hex de longitud impar");
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new Json.JsonException("Hex inválido: " + hex);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * Sobreescribe un array con ceros. Se usa para no dejar
     * datos sensibles en memoria más tiempo del necesario.
     */
    public static void borrarDeMemoria(byte[] b) {
        if (b != null) Arrays.fill(b, (byte) 0);
    }

    public static void borrarDeMemoria(char[] c) {
        if (c != null) Arrays.fill(c, '\0');
    }

    // ============================================================
    // Setup
    // ============================================================
    private static void asegurarCarpetas() {
        try {
            Files.createDirectories(DIR_DATA);
            Files.createDirectories(DIR_SERVER);
        } catch (IOException e) {
            throw new Json.JsonException("No se pudieron crear carpetas: " + e.getMessage());
        }
    }
}