// ============================================================
// Json.java
// Parser, serializador y contenedor de JSON.
// Estricto en el parseo, sin dependencias externas.
// Un solo archivo, listo para compilar.
// ============================================================
package db;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Json {

    // ============================================================
    // Excepción propia
    // ============================================================
    public static final class JsonException extends RuntimeException {
        private final int posicion;
        public JsonException(String mensaje) { this(mensaje, -1); }
        public JsonException(String mensaje, int posicion) {
            super(posicion >= 0 ? mensaje + " (posición " + posicion + ")" : mensaje);
            this.posicion = posicion;
        }
        public int getPosicion() { return posicion; }
    }

    // ============================================================
    // Tipo interno
    // ============================================================
    public enum Tipo { OBJETO, ARRAY, STRING, NUMBER, BOOLEAN, NULL }

    private final Tipo tipo;
    private final Object valor;

    private Json(Tipo tipo, Object valor) {
        this.tipo = tipo;
        this.valor = valor;
    }

    // ============================================================
    // Constructores estáticos
    // ============================================================
    public static Json object() {
        return new Json(Tipo.OBJETO, new LinkedHashMap<String, Json>());
    }

    public static Json array() {
        return new Json(Tipo.ARRAY, new ArrayList<Json>());
    }

    public static Json of(String s) {
        return s == null ? nulo() : new Json(Tipo.STRING, s);
    }

    public static Json of(long n) {
        return new Json(Tipo.NUMBER, Long.valueOf(n));
    }

    public static Json of(double n) {
        if (Double.isNaN(n) || Double.isInfinite(n)) {
            throw new JsonException("Número no finito no permitido: " + n);
        }
        return new Json(Tipo.NUMBER, Double.valueOf(n));
    }

    public static Json of(boolean b) {
        return new Json(Tipo.BOOLEAN, Boolean.valueOf(b));
    }

    public static Json nulo() {
        return new Json(Tipo.NULL, null);
    }

    // ============================================================
    // Consultas de tipo
    // ============================================================
    public Tipo tipo()        { return tipo; }
    public boolean esObjeto() { return tipo == Tipo.OBJETO; }
    public boolean esArray()  { return tipo == Tipo.ARRAY; }
    public boolean esString() { return tipo == Tipo.STRING; }
    public boolean esNumero() { return tipo == Tipo.NUMBER; }
    public boolean esBooleano(){ return tipo == Tipo.BOOLEAN; }
    public boolean esNulo()   { return tipo == Tipo.NULL; }

    // ============================================================
    // Navegación de objetos
    // ============================================================
    @SuppressWarnings("unchecked")
    private Map<String, Json> mapa() {
        if (tipo != Tipo.OBJETO) {
            throw new JsonException("No es un objeto (es " + tipo + ")");
        }
        return (Map<String, Json>) valor;
    }

    @SuppressWarnings("unchecked")
    private List<Json> lista() {
        if (tipo != Tipo.ARRAY) {
            throw new JsonException("No es un array (es " + tipo + ")");
        }
        return (List<Json>) valor;
    }

    public Json get(String clave) {
        if (tipo != Tipo.OBJETO) return null;
        return mapa().get(clave);
    }

    public Json get(int indice) {
        if (tipo != Tipo.ARRAY) return null;
        List<Json> l = lista();
        if (indice < 0 || indice >= l.size()) return null;
        return l.get(indice);
    }

    public boolean tiene(String clave) {
        return tipo == Tipo.OBJETO && mapa().containsKey(clave);
    }

    public int tamaño() {
        if (tipo == Tipo.OBJETO) return mapa().size();
        if (tipo == Tipo.ARRAY)  return lista().size();
        throw new JsonException("No tiene tamaño (es " + tipo + ")");
    }

    public Iterable<String> claves() {
        if (tipo != Tipo.OBJETO) throw new JsonException("No es objeto");
        return mapa().keySet();
    }

    public Iterable<Json> elementos() {
        if (tipo != Tipo.ARRAY) throw new JsonException("No es array");
        return lista();
    }

    // ============================================================
    // Setters / adders
    // ============================================================
    public Json set(String clave, Json v) {
        mapa().put(clave, v == null ? nulo() : v);
        return this;
    }

    public Json set(String clave, String v)  { return set(clave, of(v)); }
    public Json set(String clave, long v)    { return set(clave, of(v)); }
    public Json set(String clave, double v)  { return set(clave, of(v)); }
    public Json set(String clave, boolean v) { return set(clave, of(v)); }

    public Json add(Json v) {
        lista().add(v == null ? nulo() : v);
        return this;
    }

    public Json add(String v)  { return add(of(v)); }
    public Json add(long v)    { return add(of(v)); }
    public Json add(double v)  { return add(of(v)); }
    public Json add(boolean v) { return add(of(v)); }

    public Json quitar(String clave) {
        mapa().remove(clave);
        return this;
    }

    // ============================================================
    // Conversión de valores
    // ============================================================
    public String asString() {
        if (tipo != Tipo.STRING) {
            throw new JsonException("No es string (es " + tipo + ")");
        }
        return (String) valor;
    }

    public String asString(String porDefecto) {
        return tipo == Tipo.STRING ? (String) valor : porDefecto;
    }

    public long asLong() {
        if (tipo != Tipo.NUMBER) {
            throw new JsonException("No es número (es " + tipo + ")");
        }
        Object v = valor;
        if (v instanceof Long)   return ((Long) v).longValue();
        if (v instanceof Double) return (long) ((Double) v).doubleValue();
        throw new JsonException("Número no soportado: " + v);
    }

    public long asLong(long porDefecto) {
        return tipo == Tipo.NUMBER ? asLong() : porDefecto;
    }

    public double asDouble() {
        if (tipo != Tipo.NUMBER) {
            throw new JsonException("No es número (es " + tipo + ")");
        }
        Object v = valor;
        if (v instanceof Long)   return ((Long) v).doubleValue();
        if (v instanceof Double) return ((Double) v).doubleValue();
        throw new JsonException("Número no soportado: " + v);
    }

    public double asDouble(double porDefecto) {
        return tipo == Tipo.NUMBER ? asDouble() : porDefecto;
    }

    public boolean asBoolean() {
        if (tipo != Tipo.BOOLEAN) {
            throw new JsonException("No es booleano (es " + tipo + ")");
        }
        return ((Boolean) valor).booleanValue();
    }

    public boolean asBoolean(boolean porDefecto) {
        return tipo == Tipo.BOOLEAN ? asBoolean() : porDefecto;
    }

    // ============================================================
    // Parser
    // ============================================================
    public static Json parse(String texto) {
        if (texto == null) throw new JsonException("Texto nulo");
        Parser p = new Parser(texto);
        p.saltarEspacios();
        Json resultado = p.valor();
        p.saltarEspacios();
        if (!p.fin()) {
            throw new JsonException("Contenido sobrante tras el JSON", p.pos);
        }
        return resultado;
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) { this.s = s; this.pos = 0; }

        boolean fin() { return pos >= s.length(); }

        char actual() {
            if (fin()) throw new JsonException("Fin inesperado", pos);
            return s.charAt(pos);
        }

        void saltarEspacios() {
            while (!fin()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Json valor() {
            saltarEspacios();
            if (fin()) throw new JsonException("Fin inesperado", pos);
            char c = actual();

            if (c == '{') return objeto();
            if (c == '[') return array();
            if (c == '"') return of(string());
            if (c == 't') { esperar("true");  return of(true); }
            if (c == 'f') { esperar("false"); return of(false); }
            if (c == 'n') { esperar("null");  return nulo(); }
            if (c == '-' || (c >= '0' && c <= '9')) return numero();

            throw new JsonException("Carácter inesperado: '" + c + "'", pos);
        }

        void esperar(String palabra) {
            int n = palabra.length();
            if (pos + n > s.length() || !s.regionMatches(pos, palabra, 0, n)) {
                throw new JsonException("Se esperaba '" + palabra + "'", pos);
            }
            pos += n;
        }

        Json objeto() {
            consumir('{');
            Json obj = Json.object();
            saltarEspacios();
            if (!fin() && actual() == '}') { consumir('}'); return obj; }
            while (true) {
                saltarEspacios();
                if (actual() != '"') {
                    throw new JsonException("Se esperaba clave string", pos);
                }
                String clave = string();
                saltarEspacios();
                consumir(':');
                Json v = valor();
                obj.set(clave, v);
                saltarEspacios();
                if (fin()) throw new JsonException("Objeto sin cerrar", pos);
                char c = actual();
                if (c == ',') { consumir(','); continue; }
                if (c == '}') { consumir('}'); break; }
                throw new JsonException("Se esperaba ',' o '}'", pos);
            }
            return obj;
        }

        Json array() {
            consumir('[');
            Json arr = Json.array();
            saltarEspacios();
            if (!fin() && actual() == ']') { consumir(']'); return arr; }
            while (true) {
                Json v = valor();
                arr.add(v);
                saltarEspacios();
                if (fin()) throw new JsonException("Array sin cerrar", pos);
                char c = actual();
                if (c == ',') { consumir(','); continue; }
                if (c == ']') { consumir(']'); break; }
                throw new JsonException("Se esperaba ',' o ']'", pos);
            }
            return arr;
        }

        void consumir(char esperado) {
            if (fin() || s.charAt(pos) != esperado) {
                throw new JsonException("Se esperaba '" + esperado + "'", pos);
            }
            pos++;
        }

        String string() {
            consumir('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (fin()) throw new JsonException("String sin cerrar", pos);
                char c = s.charAt(pos++);
                if (c == '"') break;
                if (c == '\\') {
                    if (fin()) throw new JsonException("Escape incompleto", pos);
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"':  sb.append('"');  break;
                        case '\\': sb.append('\\'); break;
                        case '/':  sb.append('/');  break;
                        case 'b':  sb.append('\b'); break;
                        case 'f':  sb.append('\f'); break;
                        case 'n':  sb.append('\n'); break;
                        case 'r':  sb.append('\r'); break;
                        case 't':  sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 > s.length()) {
                                throw new JsonException("\\u incompleto", pos);
                            }
                            String hex = s.substring(pos, pos + 4);
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                            } catch (NumberFormatException ex) {
                                throw new JsonException("\\u inválido: " + hex, pos);
                            }
                            pos += 4;
                            break;
                        default:
                            throw new JsonException("Escape inválido: \\" + e, pos);
                    }
                } else if (c < 0x20) {
                    throw new JsonException(
                        "Carácter de control sin escapar en string (código " + (int) c + ")",
                        pos - 1
                    );
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        Json numero() {
            int inicio = pos;
            if (actual() == '-') pos++;
            if (fin()) throw new JsonException("Número incompleto", pos);

            if (actual() == '0') {
                pos++;
                if (!fin() && Character.isDigit(actual())) {
                    throw new JsonException("Cero inicial no permitido", pos);
                }
            } else if (actual() >= '1' && actual() <= '9') {
                while (!fin() && Character.isDigit(actual())) pos++;
            } else {
                throw new JsonException("Número inválido", pos);
            }

            boolean esDouble = false;
            if (!fin() && actual() == '.') {
                esDouble = true;
                pos++;
                if (fin() || !Character.isDigit(actual())) {
                    throw new JsonException("Falta parte decimal", pos);
                }
                while (!fin() && Character.isDigit(actual())) pos++;
            }
            if (!fin() && (actual() == 'e' || actual() == 'E')) {
                esDouble = true;
                pos++;
                if (!fin() && (actual() == '+' || actual() == '-')) pos++;
                if (fin() || !Character.isDigit(actual())) {
                    throw new JsonException("Exponente inválido", pos);
                }
                while (!fin() && Character.isDigit(actual())) pos++;
            }

            String num = s.substring(inicio, pos);
            try {
                if (esDouble) return of(Double.parseDouble(num));
                return of(Long.parseLong(num));
            } catch (NumberFormatException e) {
                throw new JsonException("Número fuera de rango: " + num, inicio);
            }
        }
    }

    // ============================================================
    // Serializador
    // ============================================================
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        escribir(sb, 0);
        return sb.toString();
    }

    public String toString(int indent) {
        StringBuilder sb = new StringBuilder();
        escribir(sb, indent);
        return sb.toString();
    }

    private void escribir(StringBuilder sb, int indent) {
        switch (tipo) {
            case NULL:
                sb.append("null");
                break;
            case BOOLEAN:
                sb.append(((Boolean) valor).booleanValue() ? "true" : "false");
                break;
            case NUMBER:
                if (valor instanceof Long) {
                    sb.append(((Long) valor).longValue());
                } else {
                    double d = ((Double) valor).doubleValue();
                    if (d == Math.floor(d) && !Double.isInfinite(d)
                        && d >= Long.MIN_VALUE && d <= Long.MAX_VALUE) {
                        sb.append((long) d).append(".0");
                    } else {
                        sb.append(d);
                    }
                }
                break;
            case STRING:
                escribirString(sb, (String) valor);
                break;
            case ARRAY: {
                List<Json> l = lista();
                if (l.isEmpty()) { sb.append("[]"); break; }
                sb.append('[');
                boolean primero = true;
                for (Json v : l) {
                    if (!primero) sb.append(',');
                    primero = false;
                    if (indent > 0) {
                        sb.append('\n');
                        sangria(sb, indent);
                    }
                    v.escribir(sb, indent > 0 ? indent + 2 : 0);
                }
                if (indent > 0) { sb.append('\n'); sangria(sb, indent - 2); }
                sb.append(']');
                break;
            }
            case OBJETO: {
                Map<String, Json> m = mapa();
                if (m.isEmpty()) { sb.append("{}"); break; }
                sb.append('{');
                boolean primero = true;
                for (Map.Entry<String, Json> e : m.entrySet()) {
                    if (!primero) sb.append(',');
                    primero = false;
                    if (indent > 0) {
                        sb.append('\n');
                        sangria(sb, indent);
                    }
                    escribirString(sb, e.getKey());
                    sb.append(':');
                    if (indent > 0) sb.append(' ');
                    e.getValue().escribir(sb, indent > 0 ? indent + 2 : 0);
                }
                if (indent > 0) { sb.append('\n'); sangria(sb, indent - 2); }
                sb.append('}');
                break;
            }
        }
    }

    private static void sangria(StringBuilder sb, int n) {
        for (int i = 0; i < n; i++) sb.append(' ');
    }

    private static void escribirString(StringBuilder sb, String s) {
        sb.append('"');
        int n = s.length();
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    // ============================================================
    // Igualdad (útil para tests y comparaciones)
    // ============================================================
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Json)) return false;
        Json otro = (Json) o;
        if (tipo != otro.tipo) return false;
        if (valor == null) return otro.valor == null;
        return valor.equals(otro.valor);
    }

    @Override
    public int hashCode() {
        return 31 * tipo.hashCode() + (valor == null ? 0 : valor.hashCode());
    }
}