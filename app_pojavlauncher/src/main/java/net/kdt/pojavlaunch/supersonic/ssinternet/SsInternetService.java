package net.kdt.pojavlaunch.supersonic.ssinternet;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;

import com.supersonic.ssinternet.core.ProviderEngine;

import net.kdt.pojavlaunch.R;
import net.kdt.pojavlaunch.Tools;

/**
 * Keeps the process (and so the tunnel) alive while SS Internet is on, and shows the required
 * foreground notification. While Provider mode is on it holds a partial wake lock, because a phone
 * that sleeps can not share its connection.
 */
public class SsInternetService extends Service {
    private static final int NOTIF_ID = 7300;
    private static final String EXTRA_STOP = "stop";

    private PowerManager.WakeLock mWakeLock;
    private final Runnable mRefresh = new Runnable() {
        @Override public void run() {
            update();
            Tools.MAIN_HANDLER.postDelayed(this, 5000);
        }
    };

    /** Starts the service if SS Internet is on, stops it if everything is off. */
    public static void sync(Context context) {
        Context app = context.getApplicationContext();
        if (SsInternetManager.get(app).anyActive()) {
            ContextCompat.startForegroundService(app, new Intent(app, SsInternetService.class));
        } else {
            app.stopService(new Intent(app, SsInternetService.class));
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && intent.getBooleanExtra(EXTRA_STOP, false)) {
            SsInternetManager m = SsInternetManager.get(this);
            m.stopProvider();
            m.stopClient();
            stopSelf();
            return START_NOT_STICKY;
        }
        Tools.buildNotificationChannel(getApplicationContext());
        Notification n = buildNotification();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST);
        } else {
            startForeground(NOTIF_ID, n);
        }
        updateWakeLock();
        Tools.MAIN_HANDLER.removeCallbacks(mRefresh);
        Tools.MAIN_HANDLER.postDelayed(mRefresh, 5000);
        return START_NOT_STICKY; // never silently restart: sharing must be switched on by the user
    }

    private void updateWakeLock() {
        boolean provider = SsInternetManager.get(this).providerOn();
        if (provider && mWakeLock == null) {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                mWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Supersonic:SsInternet");
                mWakeLock.setReferenceCounted(false);
                mWakeLock.acquire();
            }
        } else if (!provider && mWakeLock != null) {
            mWakeLock.release();
            mWakeLock = null;
        }
    }

    private Notification buildNotification() {
        SsInternetManager m = SsInternetManager.get(this);
        StringBuilder text = new StringBuilder();
        ProviderEngine p = m.provider();
        if (p != null) text.append("Sharing internet: ").append(p.connectedCount()).append(" connected");
        if (m.client() != null) {
            if (text.length() > 0) text.append(" | ");
            text.append("Using shared internet: ").append(m.client().state().name().toLowerCase(java.util.Locale.US).replace('_', ' '));
        }
        Intent stop = new Intent(this, SsInternetService.class).putExtra(EXTRA_STOP, true);
        PendingIntent stopIntent = PendingIntent.getService(this, 7302, stop,
                Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        boolean alert = m.alertActive();
        NotificationCompat.Builder b = new NotificationCompat.Builder(this, getString(R.string.notif_channel_id))
                .setSmallIcon(R.drawable.notif_icon)
                .setContentTitle("SS Internet")
                .setContentText(alert ? SsInternetManager.ALERT_TEXT : (text.length() == 0 ? "Off" : text.toString()))
                .setOngoing(true)
                .setNotificationSilent()
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Turn off", stopIntent);
        if (alert) b.setColor(0xFFD32F2F).setColorized(true); // red for the 16 seconds of the alert
        return b.build();
    }

    private void update() {
        if (!SsInternetManager.get(this).anyActive()) {
            stopSelf();
            return;
        }
        updateWakeLock();
        try {
            NotificationManagerCompat.from(this).notify(NOTIF_ID, buildNotification());
        } catch (SecurityException ignored) {
        }
    }

    @Override
    public void onDestroy() {
        Tools.MAIN_HANDLER.removeCallbacks(mRefresh);
        if (mWakeLock != null) {
            mWakeLock.release();
            mWakeLock = null;
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) { return null; }
}
