package it.daryops.tpx;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Client per il pannello TP-Link (firmware Archer AX72 / AX72 Pro).
 * Porting del protocollo di login della libreria tplinkrouterc6u (client AX72):
 * password RSA PKCS#1 v1.5, firma RSA-OAEP a blocchi annidati, dati AES-128-CBC.
 */
public class RouterClient {
    private final String host;      // es. https://192.168.0.1
    private final String password;
    private final String username = "admin";
    private String pwdNN, pwdEE, nn, ee;
    private long seq;
    private String stok = "", sysauth = "";
    private boolean logged = false;
    private String scheme = "";           // "ax72" (SHA256+OAEP) oppure "std" (MD5+PKCS1)
    private String lastLoginBody = "";
    private final String aesKey, aesIv;   // 16 caratteri esadecimali ciascuno
    private static final int TIMEOUT = 15000;

    public RouterClient(String host, String password) {
        this.host = host.replaceAll("/+$", "");
        this.password = password;
        SecureRandom r = new SecureRandom();
        this.aesKey = randHex(r);
        this.aesIv = randHex(r);
    }

    public boolean isLogged() { return logged; }
    public String getScheme() { return scheme; }
    public void setPreferredScheme(String s) { if (s != null) preferred = s; }
    private String preferred = "";
    public String getHost() { return host; }

    private static String randHex(SecureRandom r) {
        byte[] b = new byte[8];
        r.nextBytes(b);
        return hex(b);
    }

    // ---------------- login ----------------
    public void login() throws Exception {
        requestKeys();
        if (preferred.equals("plain") || host.startsWith("https")) {
            loginPlain();
            return;
        }
        String first = !preferred.isEmpty() ? preferred : (nn.length() == 128 ? "ax72" : "std");
        String second = first.equals("ax72") ? "std" : "ax72";
        Exception err;
        try {
            loginWith(first);
            return;
        } catch (Exception e) {
            err = e;   // anche "password errata" può dipendere dallo schema sbagliato: proviamo l'altro
        }
        try {
            requestKeys();
            loginWith(second);
        } catch (WrongPassword w) {
            throw w;
        } catch (Exception e2) {
            if (err instanceof WrongPassword) throw (WrongPassword) err;
            throw new Exception("Login non riuscito. Dettagli: " + err.getMessage() + " | " + e2.getMessage());
        }
    }

    /** In https il pannello non cifra i dati: solo la password viaggia cifrata con RSA. */
    private void loginPlain() throws Exception {
        scheme = "plain";
        logged = false;
        String crypted = rsaPkcs1Hex(password.getBytes(StandardCharsets.UTF_8), pwdNN, pwdEE);
        String form = "password=" + crypted + "&operation=login&confirm=true";
        Resp res = post(host + "/cgi-bin/luci/;stok=/login?form=login", form, null);
        lastLoginBody = res.body;
        if (res.body.contains("login failed") || res.body.contains("-40401")) throw new WrongPassword();
        Matcher m = Pattern.compile("\"stok\"\\s*:\\s*\"([^\"]+)\"").matcher(res.body);
        if (!m.find()) throw new Exception("[https] risposta " + res.code + ": " + shorten(res.body));
        stok = m.group(1);
        sysauth = "";
        if (res.cookies != null) {
            for (String c : res.cookies) {
                Matcher cm = Pattern.compile("sysauth=([^;]+)").matcher(c);
                if (cm.find()) sysauth = cm.group(1);
            }
        }
        logged = true;
    }

    public static class WrongPassword extends Exception {
        public WrongPassword() { super("Password errata"); }
    }

    private void loginWith(String sch) throws Exception {
        scheme = sch;
        logged = false;
        Resp res = tryLogin();
        lastLoginBody = res.body;
        String plain;
        try {
            plain = decryptEnvelope(res.body);
        } catch (Exception e) {
            throw new Exception("[" + sch + "] risposta " + res.code + ": " + shorten(res.body));
        }
        if (plain.contains("login failed") || plain.contains("-40401")) throw new WrongPassword();
        Matcher m = Pattern.compile("\"stok\"\\s*:\\s*\"([^\"]+)\"").matcher(plain);
        if (!m.find()) {
            throw new Exception("[" + sch + "] " + shorten(plain));
        }
        stok = m.group(1);
        sysauth = "";
        if (res.cookies != null) {
            for (String c : res.cookies) {
                Matcher cm = Pattern.compile("sysauth=([^;]+)").matcher(c);
                if (cm.find()) sysauth = cm.group(1);
            }
        }
        logged = true;
    }

    private void requestKeys() throws Exception {
        Resp k = post(host + "/cgi-bin/luci/;stok=/login?form=keys&operation=read", null, null);
        Matcher pm = Pattern.compile("\"password\"\\s*:\\s*\\[\\s*\"([0-9a-fA-F]+)\"\\s*,\\s*\"([0-9a-fA-F]+)\"").matcher(k.body);
        if (!pm.find()) throw new Exception("Router non raggiungibile o modello non supportato");
        pwdNN = pm.group(1); pwdEE = pm.group(2);

        Resp a = post(host + "/cgi-bin/luci/;stok=/login?form=auth&operation=read", null, null);
        Matcher km = Pattern.compile("\"key\"\\s*:\\s*\\[\\s*\"([0-9a-fA-F]+)\"\\s*,\\s*\"([0-9a-fA-F]+)\"").matcher(a.body);
        Matcher sm = Pattern.compile("\"seq\"\\s*:\\s*\"?(\\d+)").matcher(a.body);
        if (!km.find() || !sm.find()) throw new Exception("Risposta auth non valida");
        nn = km.group(1); ee = km.group(2);
        seq = Long.parseLong(sm.group(1));
    }

    private Resp tryLogin() throws Exception {
        String crypted = rsaPkcs1Hex(password.getBytes(StandardCharsets.UTF_8), pwdNN, pwdEE);
        String data = "operation=login&password=" + crypted + (scheme.equals("std") ? "&confirm=true" : "");
        return post(host + "/cgi-bin/luci/;stok=/login?form=login", prepare(data), null);
    }

    public void logout() {
        if (!logged) return;
        try {
            request("admin/system?form=logout", "{\"operation\":\"write\"}");
        } catch (Exception ignored) { }
        logged = false;
        stok = "";
        sysauth = "";
    }

    // ---------------- richieste ----------------
    /** Invia una richiesta (corpo JSON in chiaro) e restituisce il JSON decifrato completo. */
    public String request(String path, String jsonPlain) throws Exception {
        if (!logged) throw new Exception("Non autenticato");
        Matcher om = Pattern.compile("\"operation\"\\s*:\\s*\"([\\w-]+)\"").matcher(jsonPlain);
        String url = host + "/cgi-bin/luci/;stok=" + stok + "/" + path.replaceAll("^/+", "");
        if (om.find() && !url.contains("operation=")) url += (url.contains("?") ? "&" : "?") + "operation=" + om.group(1);
        boolean plain = scheme.equals("plain");
        if (plain) url = host + "/cgi-bin/luci/;stok=" + stok + "/" + path.replaceAll("^/+", "");
        Resp r = post(url, plain ? jsonToForm(jsonPlain) : prepare(jsonPlain), sysauth);
        if (r.code == 403 || r.code == 401) {
            logged = false;
            throw new SessionExpired();
        }
        return plain ? r.body : decryptEnvelope(r.body);
    }

    public static class SessionExpired extends Exception {
        public SessionExpired() { super("Sessione scaduta"); }
    }

    private String prepare(String plain) throws Exception {
        String enc = aesEncrypt(plain);
        long seqLen = seq + enc.length();
        String sign;
        if (scheme.equals("std")) {
            String hash = md5Hex((username + password).getBytes(StandardCharsets.UTF_8));
            String str = (logged ? "" : "k=" + aesKey + "&i=" + aesIv + "&") + "h=" + hash + "&s=" + seqLen;
            StringBuilder sb = new StringBuilder();
            for (int o = 0; o < str.length(); o += 53)
                sb.append(rsaPkcs1Hex(str.substring(o, Math.min(str.length(), o + 53)).getBytes(StandardCharsets.US_ASCII), nn, ee));
            sign = sb.toString();
        } else {
            String hash = sha256Hex((username + password).getBytes(StandardCharsets.UTF_8));
            sign = buildSignature(seqLen, hash);
        }
        return "sign=" + URLEncoder.encode(sign, "UTF-8") + "&data=" + URLEncoder.encode(enc, "UTF-8");
    }

    private String buildSignature(long seqLen, String hash) throws Exception {
        String s = "k=" + aesKey + "&i=" + aesIv + "&h=" + hash + "&s=" + seqLen;
        int modBytes = nn.length() / 2;
        int inner = Math.min(53, modBytes - 2 * 20 - 2);
        StringBuilder sign = new StringBuilder();
        for (int o = 0; o < s.length(); o += 53) {
            byte[] outer = s.substring(o, Math.min(s.length(), o + 53)).getBytes(StandardCharsets.US_ASCII);
            for (int i = 0; i < outer.length; i += inner) {
                int end = Math.min(outer.length, i + inner);
                byte[] chunk = new byte[end - i];
                System.arraycopy(outer, i, chunk, 0, chunk.length);
                sign.append(rsaOaepHex(chunk, nn, ee));
            }
        }
        return sign.toString();
    }

    private String decryptEnvelope(String body) throws Exception {
        Matcher m = Pattern.compile("\"data\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"").matcher(body);
        if (!m.find()) throw new Exception("Risposta non cifrata: " + shorten(body));
        return aesDecrypt(m.group(1));
    }

    // ---------------- JSON -> form (come "serialize" del pannello TP-Link) ----------------
    static String jsonToForm(String json) throws Exception {
        StringBuilder out = new StringBuilder();
        int[] i = {skipWs(json, 0)};
        if (i[0] >= json.length() || json.charAt(i[0]) != '{') throw new Exception("JSON non valido");
        i[0] = skipWs(json, i[0] + 1);
        if (json.charAt(i[0]) == '}') return "";
        while (true) {
            String key = readString(json, i);
            i[0] = skipWs(json, i[0]);
            if (json.charAt(i[0]) != ':') throw new Exception("JSON non valido");
            i[0] = skipWs(json, i[0] + 1);
            String val;
            if (json.charAt(i[0]) == '"') {
                val = readString(json, i);
            } else {
                int start = i[0];
                i[0] = skipValue(json, i[0]);
                val = json.substring(start, i[0]).trim();
            }
            if (!val.equals("null")) {
                if (out.length() > 0) out.append('&');
                out.append(URLEncoder.encode(key, "UTF-8").replace("+", "%20")).append('=')
                   .append(URLEncoder.encode(val, "UTF-8").replace("+", "%20"));
            }
            i[0] = skipWs(json, i[0]);
            char c = json.charAt(i[0]);
            if (c == ',') { i[0] = skipWs(json, i[0] + 1); continue; }
            if (c == '}') break;
            throw new Exception("JSON non valido");
        }
        return out.toString();
    }

    private static int skipWs(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return i;
    }

    private static String readString(String s, int[] i) throws Exception {
        if (s.charAt(i[0]) != '"') throw new Exception("JSON non valido");
        StringBuilder sb = new StringBuilder();
        int p = i[0] + 1;
        while (p < s.length()) {
            char c = s.charAt(p);
            if (c == '"') { i[0] = p + 1; return sb.toString(); }
            if (c == '\\') {
                char n = s.charAt(++p);
                switch (n) {
                    case 'n': sb.append('\n'); break;
                    case 't': sb.append('\t'); break;
                    case 'r': sb.append('\r'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'u': sb.append((char) Integer.parseInt(s.substring(p + 1, p + 5), 16)); p += 4; break;
                    default: sb.append(n);
                }
                p++;
                continue;
            }
            sb.append(c);
            p++;
        }
        throw new Exception("JSON non valido");
    }

    /** Salta un valore non-stringa (numero, true/false/null, oggetto, array) e ne restituisce la fine. */
    private static int skipValue(String s, int i) {
        int depth = 0;
        boolean inStr = false;
        for (; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') i++;
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') inStr = true;
            else if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') { if (depth == 0) return i; depth--; if (depth == 0) return i + 1; }
            else if (c == ',' && depth == 0) return i;
        }
        return i;
    }

    // ---------------- crittografia ----------------
    private String aesEncrypt(String plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey.getBytes(StandardCharsets.US_ASCII), "AES"),
                new IvParameterSpec(aesIv.getBytes(StandardCharsets.US_ASCII)));
        return Base64.getEncoder().encodeToString(c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
    }

    private String aesDecrypt(String b64) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey.getBytes(StandardCharsets.US_ASCII), "AES"),
                new IvParameterSpec(aesIv.getBytes(StandardCharsets.US_ASCII)));
        byte[] out = c.doFinal(Base64.getDecoder().decode(b64));
        int pad = out.length > 0 ? (out[out.length - 1] & 0xff) : 0;
        int len = (pad > 0 && pad <= 16 && pad <= out.length) ? out.length - pad : out.length;
        return new String(out, 0, len, StandardCharsets.UTF_8);
    }

    private static PublicKey pub(String nHex, String eHex) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(new BigInteger(nHex, 16), new BigInteger(eHex, 16)));
    }

    private static String rsaPkcs1Hex(byte[] data, String nHex, String eHex) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub(nHex, eHex));
        return padHex(hex(c.doFinal(data)), nHex.length());
    }

    private static String rsaOaepHex(byte[] data, String nHex, String eHex) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub(nHex, eHex));
        return padHex(hex(c.doFinal(data)), nHex.length());
    }

    private static String padHex(String h, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = h.length(); i < len; i++) sb.append('0');
        return sb.append(h).toString();
    }

    private static String md5Hex(byte[] b) throws Exception {
        return hex(MessageDigest.getInstance("MD5").digest(b));
    }

    private static String sha256Hex(byte[] b) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static String shorten(String s) {
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }

    // ---------------- HTTP ----------------
    static class Resp {
        int code;
        String body;
        List<String> cookies;
    }

    private Resp post(String url, String form, String cookie) throws Exception {
        HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
        if (con instanceof HttpsURLConnection) trustAll((HttpsURLConnection) con);
        con.setConnectTimeout(TIMEOUT);
        con.setReadTimeout(TIMEOUT);
        con.setRequestMethod("POST");
        con.setInstanceFollowRedirects(false);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setRequestProperty("Referer", host + "/webpages/index.html");
        if (cookie != null && !cookie.isEmpty()) con.setRequestProperty("Cookie", "sysauth=" + cookie);
        con.setDoOutput(true);
        byte[] payload = (form == null ? "" : form).getBytes(StandardCharsets.UTF_8);
        con.setFixedLengthStreamingMode(payload.length);
        try (OutputStream os = con.getOutputStream()) { os.write(payload); }
        Resp r = new Resp();
        r.code = con.getResponseCode();
        InputStream is = r.code >= 400 ? con.getErrorStream() : con.getInputStream();
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        if (is != null) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
            is.close();
        }
        r.body = bo.toString("UTF-8");
        Map<String, List<String>> h = con.getHeaderFields();
        for (Map.Entry<String, List<String>> e : h.entrySet())
            if (e.getKey() != null && e.getKey().equalsIgnoreCase("Set-Cookie")) r.cookies = e.getValue();
        con.disconnect();
        if (r.code >= 300 && r.code < 400) throw new Exception("Redirect dal router (" + r.code + ")");
        return r;
    }

    // Il router usa un certificato auto-firmato: lo accettiamo solo per indirizzi della rete locale.
    private static void trustAll(HttpsURLConnection c) throws Exception {
        String h = c.getURL().getHost();
        if (!(h.startsWith("192.168.") || h.startsWith("10.") || h.equals("tplinkwifi.net"))) return;
        TrustManager[] tm = {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] a, String b) { }
            public void checkServerTrusted(X509Certificate[] a, String b) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, new SecureRandom());
        c.setSSLSocketFactory(ctx.getSocketFactory());
        HostnameVerifier hv = (hostname, session) -> true;
        c.setHostnameVerifier(hv);
    }
}
