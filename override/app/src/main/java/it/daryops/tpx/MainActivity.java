package it.daryops.tpx;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class MainActivity extends Activity {
    private WebView web;
    private SharedPreferences prefs;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture<?> idleLogout;
    private RouterClient client;          // usato solo dal thread worker
    private static final long IDLE_SECONDS = 25;

    @SuppressLint({"SetJavaScriptEnabled", "AddJavascriptInterface"})
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        prefs = getSharedPreferences("tpx", MODE_PRIVATE);
        getWindow().setStatusBarColor(Color.parseColor("#0b1220"));
        getWindow().setNavigationBarColor(Color.parseColor("#0d1526"));
        web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#0b1220"));
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(true);
        web.setWebViewClient(new WebViewClient());
        web.addJavascriptInterface(new Bridge(), "Android");
        setContentView(web);
        web.loadUrl("file:///android_asset/index.html");
    }

    @Override
    public void onBackPressed() {
        if (web.canGoBack()) web.goBack();
        else super.onBackPressed();
    }

    @Override
    protected void onStop() {
        super.onStop();
        worker.submit(this::closeSession);   // libera il router quando esci dall'app
    }

    @Override
    protected void onDestroy() {
        worker.submit(this::closeSession);
        worker.shutdown();
        timer.shutdown();
        super.onDestroy();
    }

    private void closeSession() {
        if (client != null) {
            client.logout();
            client = null;
        }
    }

    private void scheduleIdleLogout() {
        if (idleLogout != null) idleLogout.cancel(false);
        idleLogout = timer.schedule(() -> worker.submit(this::closeSession), IDLE_SECONDS, TimeUnit.SECONDS);
    }

    /** Ottiene una sessione attiva: prima http (il pannello cifra i dati solo in http), poi https. */
    private RouterClient session() throws Exception {
        if (client != null && client.isLogged()) return client;
        String pwd = prefs.getString("pwd", "");
        if (pwd.isEmpty()) throw new Exception("Password non impostata");
        String saved = prefs.getString("host", "");
        String[] hosts = saved.isEmpty()
                ? new String[]{"http://192.168.0.1", "https://192.168.0.1"}
                : new String[]{saved};
        Exception last = null;
        for (String h : hosts) {
            try {
                RouterClient c = new RouterClient(h, pwd);
                c.setPreferredScheme(prefs.getString("scheme", ""));
                c.login();
                prefs.edit().putString("host", h).putString("scheme", c.getScheme()).apply();
                client = c;
                return c;
            } catch (Exception e) {
                last = e;
                if (e instanceof RouterClient.WrongPassword) break;
            }
        }
        if (saved.length() > 0) prefs.edit().remove("host").apply();
        throw last != null ? last : new Exception("Router non raggiungibile");
    }

    private String doCall(String path, String json) throws Exception {
        try {
            return session().request(path, json);
        } catch (RouterClient.SessionExpired e) {
            client = null;
            return session().request(path, json);      // un secondo tentativo con nuovo login
        } catch (java.io.IOException e) {
            client = null;
            throw new Exception("Router non raggiungibile: sei collegato al Wi-Fi di casa?");
        }
    }

    private void reply(String id, boolean ok, String res) {
        String js = "window.__cb(" + JSONObject.quote(id) + "," + ok + "," + JSONObject.quote(res == null ? "" : res) + ")";
        web.post(() -> web.evaluateJavascript(js, null));
    }

    class Bridge {
        @JavascriptInterface
        public void call(String id, String path, String json) {
            worker.submit(() -> {
                try {
                    String r = doCall(path, json);
                    scheduleIdleLogout();
                    reply(id, true, r);
                } catch (Exception e) {
                    reply(id, false, e.getMessage() == null ? e.toString() : e.getMessage());
                }
            });
        }

        @JavascriptInterface
        public void setPassword(String pwd) {
            worker.submit(() -> {
                closeSession();
                prefs.edit().putString("pwd", pwd).remove("host").remove("scheme").apply();
            });
        }

        @JavascriptInterface
        public boolean hasPassword() {
            return !prefs.getString("pwd", "").isEmpty();
        }

        @JavascriptInterface
        public String version() {
            return BuildConfig.VERSION_NAME;
        }
    }
}
