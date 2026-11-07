package net.kdt.pojavlaunch.supersonic.ssinternet;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import com.supersonic.ssinternet.core.ClientEngine;
import com.supersonic.ssinternet.core.EgressPolicy;
import com.supersonic.ssinternet.core.Identity;
import com.supersonic.ssinternet.core.ProviderEngine;
import com.supersonic.ssinternet.core.RouteMonitor;
import com.supersonic.ssinternet.core.SsProxySelector;

import net.kdt.pojavlaunch.R;
import net.kdt.pojavlaunch.Tools;

import java.io.File;
import java.net.ProxySelector;

/**
 * Owns the SS Internet engines of this app process and the user's settings.
 *
 * Client side: when Client mode is on and "use for Supersonic's own traffic" is on, every java.net / OkHttp
 * request of the launcher process (version and asset downloads, mod and addon browsing) goes through the
 * provider. If the provider's connection fails, a red alert "Some problem detect on SS Internet" is shown for
 * 16 seconds and, if allowed, traffic falls back to the user's own internet until the provider is back.
 * NOT covered yet: the game's own multiplayer connections (separate process, Netty) - that needs VpnService.
 */
public final class SsInternetManager {
    private static final String PREFS = "ss_internet";
    private static final int NOTIF_APPROVAL = 7301;
    private static final int NOTIF_ALERT = 7303;
    private static final String ALERT_CHANNEL = "ss_internet_alert";
    public static final long ALERT_MILLIS = 16_000;
    public static final String ALERT_TEXT = "Some problem detect on SS Internet";

    private static SsInternetManager sInstance;

    public static synchronized SsInternetManager get(Context context) {
        if (sInstance == null) sInstance = new SsInternetManager(context.getApplicationContext());
        return sInstance;
    }

    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final File mDir;
    private Identity mIdentity;
    private ProviderEngine mProvider;
    private ClientEngine mClient;
    private RouteMonitor mMonitor;
    private ProxySelector mPreviousSelector;
    private ProxySelector mOurSelector;
    private volatile long mAlertUntil;
    private boolean mLauncherStarted;

    private SsInternetManager(Context context) {
        mContext = context;
        mPrefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        mDir = new File(context.getFilesDir(), "ssinternet");
    }

    // ------------------------------------------------------------------ settings

    public String relayHost() { return mPrefs.getString("relay_host", ""); }
    public int relayPort() { return mPrefs.getInt("relay_port", 8443); }
    public String relayPin() { return mPrefs.getString("relay_pin", ""); }

    public void saveRelay(String host, int port, String pin) {
        mPrefs.edit().putString("relay_host", host).putInt("relay_port", port).putString("relay_pin", pin).apply();
    }

    public boolean relayConfigured() { return !relayHost().isEmpty(); }

    public String providerName() { return mPrefs.getString("provider_name", "SS Internet"); }
    public String providerCountry() { return mPrefs.getString("provider_country", ""); }
    /** Default off: a private setup where friends enter the provider ID themselves. */
    public boolean providerListed() { return mPrefs.getBoolean("provider_listed", false); }
    /** Open mode, default on: new devices are let in without asking. The owner can still block, limit and remove. */
    public boolean providerAutoApprove() { return mPrefs.getBoolean("provider_auto_approve", true); }
    public int providerMaxClients() { return mPrefs.getInt("provider_max", 5); }
    public int providerLimitKbps() { return mPrefs.getInt("provider_limit_kbps", 0); }
    public int providerCapMb() { return mPrefs.getInt("provider_cap_mb", 0); }

    public void saveProvider(String name, String country, boolean listed, boolean autoApprove, int max, int limitKbps, int capMb) {
        mPrefs.edit().putString("provider_name", name).putString("provider_country", country)
                .putBoolean("provider_listed", listed).putBoolean("provider_auto_approve", autoApprove).putInt("provider_max", max)
                .putInt("provider_limit_kbps", limitKbps).putInt("provider_cap_mb", capMb).apply();
    }

    public String clientProviderId() { return mPrefs.getString("client_provider_id", ""); }
    public int clientProxyPort() { return mPrefs.getInt("client_proxy_port", 1080); }

    public void saveClient(String providerId, int proxyPort) {
        mPrefs.edit().putString("client_provider_id", providerId).putInt("client_proxy_port", proxyPort).apply();
    }

    /** Default on: Supersonic's own traffic uses the provider's internet. */
    public boolean routeEnabled() { return mPrefs.getBoolean("route_enabled", true); }
    /** Default on: if the provider's connection fails, use the user's own internet instead of failing. */
    public boolean fallbackToOwnInternet() { return mPrefs.getBoolean("fallback_own", true); }
    /** Default on: Client mode connects by itself when the launcher opens (only if relay and provider ID are set). */
    public boolean autoStartClient() { return mPrefs.getBoolean("auto_client", true); }

    public synchronized void setRouteEnabled(boolean v) {
        mPrefs.edit().putBoolean("route_enabled", v).apply();
        if (mMonitor != null) mMonitor.setEnabled(v);
    }

    public synchronized void setFallbackToOwnInternet(boolean v) {
        mPrefs.edit().putBoolean("fallback_own", v).apply();
        if (mMonitor != null) mMonitor.setFallbackToOwnInternet(v);
    }

    public void setAutoStartClient(boolean v) { mPrefs.edit().putBoolean("auto_client", v).apply(); }

    public long clientLifetimeDown() { return mPrefs.getLong("client_total_down", 0); }
    public long clientLifetimeUp() { return mPrefs.getLong("client_total_up", 0); }

    // ------------------------------------------------------------------ identity

    public synchronized Identity identity() throws Exception {
        if (mIdentity == null) mIdentity = Identity.loadOrCreate(mDir, "supersonic-device");
        return mIdentity;
    }

    /**
     * Panic button: new device ID. Everything stops. People who had your old provider ID can no longer
     * reach you until you give them the new one. Their approvals stay in the list.
     */
    public synchronized void resetIdentity() {
        stopProvider();
        stopClient();
        new File(mDir, "identity.key").delete();
        new File(mDir, "identity.crt").delete();
        mIdentity = null;
    }

    // ------------------------------------------------------------------ launcher start

    /** Called once per launcher process start. Client mode is the only thing that may start by itself. */
    public synchronized void onLauncherStart() {
        if (mLauncherStarted) return;
        mLauncherStarted = true;
        if (!autoStartClient() || !relayConfigured() || !Identity.isValidId(clientProviderId())) return;
        Thread t = new Thread(() -> {
            try {
                startClient();
            } catch (Exception ignored) {
                // the user sees the state in Settings > SS Internet
            }
        }, "ss-auto-client");
        t.setDaemon(true);
        t.start();
    }

    // ------------------------------------------------------------------ provider

    public synchronized ProviderEngine provider() { return mProvider; }

    public synchronized boolean providerOn() { return mProvider != null; }

    public synchronized void startProvider() throws Exception {
        if (mProvider != null) return;
        if (!relayConfigured()) throw new IllegalStateException("Enter the relay server first.");
        ProviderEngine.Config c = new ProviderEngine.Config();
        c.name = providerName();
        c.country = providerCountry();
        c.listed = providerListed();
        c.autoApprove = providerAutoApprove();
        c.maxClients = Math.max(1, providerMaxClients());
        c.perClientBytesPerSec = providerLimitKbps() * 1000L / 8;
        c.totalCapBytes = providerCapMb() * 1_000_000L;
        c.policy = new EgressPolicy();
        ProviderEngine p = new ProviderEngine(mDir, identity(), relayHost(), relayPort(), relayPin(), c, this::onProviderEvent);
        p.start();
        mProvider = p;
        SsInternetService.sync(mContext);
    }

    public synchronized void stopProvider() {
        if (mProvider == null) return;
        mProvider.stop();
        mProvider = null;
        NotificationManagerCompat.from(mContext).cancel(NOTIF_APPROVAL);
        SsInternetService.sync(mContext);
    }

    private void onProviderEvent(String message) {
        if (!message.startsWith("Approval request")) return;
        Tools.buildNotificationChannel(mContext);
        Notification n = new NotificationCompat.Builder(mContext, mContext.getString(R.string.notif_channel_id))
                .setSmallIcon(R.drawable.notif_icon)
                .setContentTitle("SS Internet")
                .setContentText("A device is asking to use your internet. Open Settings > SS Internet to approve or block it.")
                .setAutoCancel(true)
                .build();
        try {
            NotificationManagerCompat.from(mContext).notify(NOTIF_APPROVAL, n);
        } catch (SecurityException ignored) { // notification permission not granted
        }
    }

    // ------------------------------------------------------------------ client

    public synchronized ClientEngine client() { return mClient; }

    public synchronized boolean clientOn() { return mClient != null; }

    public synchronized RouteMonitor monitor() { return mMonitor; }

    public synchronized void startClient() throws Exception {
        if (mClient != null) return;
        if (!relayConfigured()) throw new IllegalStateException("Enter the relay server first.");
        if (!Identity.isValidId(clientProviderId())) throw new IllegalStateException("Enter a valid provider ID first.");
        final ClientEngine c = new ClientEngine(identity(), relayHost(), relayPort(), relayPin(), clientProviderId(), clientProxyPort());
        c.start();
        mClient = c;

        mMonitor = new RouteMonitor(new RouteMonitor.Health() {
            @Override public boolean usable() { return c.isUsable(); }
            @Override public boolean connecting() { return c.isConnecting(); }
        }, new RouteMonitor.Listener() {
            @Override public void onProblem() { showProblemAlert(); }
            @Override public void onRecovered() { clearProblemAlert(); }
        }, 8000);
        mMonitor.setEnabled(routeEnabled());
        mMonitor.setFallbackToOwnInternet(fallbackToOwnInternet());

        mPreviousSelector = ProxySelector.getDefault();
        mOurSelector = new SsProxySelector(mMonitor, () -> {
            ClientEngine e = mClient;
            return e == null ? -1 : e.socksPort();
        });
        ProxySelector.setDefault(mOurSelector);
        SsInternetService.sync(mContext);
    }

    public synchronized void stopClient() {
        if (mClient == null) return;
        long down = mClient.downBytes(), up = mClient.upBytes();
        if (ProxySelector.getDefault() == mOurSelector) ProxySelector.setDefault(mPreviousSelector);
        mOurSelector = null;
        if (mMonitor != null) mMonitor.stop();
        mMonitor = null;
        mClient.stop();
        mClient = null;
        mPrefs.edit().putLong("client_total_down", clientLifetimeDown() + down)
                .putLong("client_total_up", clientLifetimeUp() + up).apply();
        clearProblemAlert();
        SsInternetService.sync(mContext);
    }

    public synchronized boolean anyActive() { return mProvider != null || mClient != null; }

    // ------------------------------------------------------------------ problem alert (red, 16 seconds)

    public boolean alertActive() { return System.currentTimeMillis() < mAlertUntil; }

    private void showProblemAlert() {
        mAlertUntil = System.currentTimeMillis() + ALERT_MILLIS;
        Context c = mContext;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(ALERT_CHANNEL, "SS Internet problems", NotificationManager.IMPORTANCE_HIGH);
            NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) nm.createNotificationChannel(ch);
        }
        Notification n = new NotificationCompat.Builder(c, ALERT_CHANNEL)
                .setSmallIcon(R.drawable.notif_icon)
                .setContentTitle("SS Internet")
                .setContentText(ALERT_TEXT)
                .setColor(0xFFD32F2F)
                .setColorized(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ERROR)
                .setAutoCancel(true)
                .setTimeoutAfter(ALERT_MILLIS)
                .build();
        try {
            NotificationManagerCompat.from(c).notify(NOTIF_ALERT, n);
        } catch (SecurityException ignored) { // notification permission not granted
        }
        SsInternetService.sync(c); // the always-visible service notification turns red too
        Tools.MAIN_HANDLER.postDelayed(() -> {
            if (!alertActive()) {
                NotificationManagerCompat.from(mContext).cancel(NOTIF_ALERT);
                SsInternetService.sync(mContext);
            }
        }, ALERT_MILLIS + 200);
    }

    private void clearProblemAlert() {
        mAlertUntil = 0;
        NotificationManagerCompat.from(mContext).cancel(NOTIF_ALERT);
        SsInternetService.sync(mContext);
    }
}
