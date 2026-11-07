package net.kdt.pojavlaunch.supersonic.ssinternet;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.supersonic.ssinternet.core.ApprovalStore;
import com.supersonic.ssinternet.core.ClientEngine;
import com.supersonic.ssinternet.core.Identity;
import com.supersonic.ssinternet.core.ProviderEngine;
import com.supersonic.ssinternet.core.RelayLink;

import net.kdt.pojavlaunch.PojavApplication;
import net.kdt.pojavlaunch.R;
import net.kdt.pojavlaunch.Tools;
import net.kdt.pojavlaunch.supersonic.SupersonicUi;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Settings > SS Internet. Everything is controlled here: relay server, Provider mode (share my internet),
 * Client mode (use a provider's internet). All numbers shown are measured by the engines, none are estimates.
 */
public class SsInternetFragment extends Fragment {
    public static final String TAG = "SsInternetFragment";

    private SsInternetManager mgr;
    private Context ctx;

    private EditText relayHost, relayPort, relayPin;
    private EditText provName, provCountry, provMax, provLimit, provCap;
    private SwitchCompat provListed, provOpen, provSwitch, clientSwitch, routeSw, fallbackSw, autoSw;
    private TextView provStatus, provStats, myId1, pendingTitle;
    private LinearLayout pendingBox, usersBox, approvedBox;
    private EditText clientProviderId, clientProxyPort;
    private TextView clientStatus, clientStats, clientHow;

    private String pendingSig = "", approvedSig = "";
    /** True between a tap on a switch and the moment the engine really exists, so the refresh does not flip the switch back. */
    private volatile boolean provStarting, clientStarting;

    private final Runnable mRefresh = new Runnable() {
        @Override public void run() {
            refresh();
            Tools.MAIN_HANDLER.postDelayed(this, 1000);
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle state) {
        ctx = requireContext();
        mgr = SsInternetManager.get(ctx);
        ScrollView scroll = new ScrollView(ctx);
        scroll.setFillViewport(true);
        LinearLayout root = new LinearLayout(ctx);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(12), dp(6), dp(12), dp(24));
        scroll.addView(root, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        buildRelayCard(root);
        buildProviderCard(root);
        buildClientCard(root);
        return scroll;
    }

    @Override public void onResume() {
        super.onResume();
        Tools.MAIN_HANDLER.post(mRefresh);
    }

    @Override public void onPause() {
        super.onPause();
        Tools.MAIN_HANDLER.removeCallbacks(mRefresh);
        saveFields();
    }

    // ------------------------------------------------------------------ cards

    private void buildRelayCard(LinearLayout root) {
        LinearLayout c = card(root, "Relay server",
                "SS Internet connects through a relay server that you run (it needs a public IP). Both the provider and the client enter the same address. The relay only moves encrypted bytes; it can not read your traffic.");
        relayHost = field(c, "Relay host (e.g. relay.example.com)", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI, mgr.relayHost());
        relayPort = field(c, "Port", InputType.TYPE_CLASS_NUMBER, String.valueOf(mgr.relayPort()));
        relayPin = field(c, "Relay ID (only for a self-signed relay, leave empty for a normal certificate)", InputType.TYPE_CLASS_TEXT, mgr.relayPin());
        button(c, "Save relay", true, v -> {
            if (saveRelay()) toast("Saved");
        });
    }

    private void buildProviderCard(LinearLayout root) {
        LinearLayout c = card(root, "Provider: share my internet",
                "Other devices, anywhere in the world, can use this phone's internet connection, but only devices you approve. No Wi-Fi hotspot or phone setting is needed. Traffic uses your mobile data or Wi-Fi quota and goes out with your IP address.");
        provSwitch = new SwitchCompat(ctx);
        provSwitch.setText("Provider mode");
        provSwitch.setTextColor(color(R.color.primary_text));
        c.addView(provSwitch);
        provSwitch.setOnClickListener(v -> onProviderToggle());

        provStatus = body(c, "");
        provName = field(c, "Name shown in the directory", InputType.TYPE_CLASS_TEXT, mgr.providerName());
        provCountry = field(c, "Country code (optional, e.g. BD)", InputType.TYPE_CLASS_TEXT, mgr.providerCountry());
        provListed = new SwitchCompat(ctx);
        provListed.setText("List me in the public directory");
        provListed.setTextColor(color(R.color.primary_text));
        provListed.setChecked(mgr.providerListed());
        c.addView(provListed);
        provOpen = new SwitchCompat(ctx);
        provOpen.setText("Open mode: let new devices in automatically");
        provOpen.setTextColor(color(R.color.primary_text));
        provOpen.setChecked(mgr.providerAutoApprove());
        c.addView(provOpen);
        body(c, "Open mode: anyone who has your provider ID connects without asking. You can still block, limit or remove any device. Turn it off to approve every new device by hand.");
        provMax = field(c, "Max users at the same time", InputType.TYPE_CLASS_NUMBER, String.valueOf(mgr.providerMaxClients()));
        provLimit = field(c, "Speed limit per user in kbit/s (0 = none)", InputType.TYPE_CLASS_NUMBER, String.valueOf(mgr.providerLimitKbps()));
        provCap = field(c, "Data limit in MB per run (0 = none)", InputType.TYPE_CLASS_NUMBER, String.valueOf(mgr.providerCapMb()));
        body(c, "Name, listing, limits apply when you switch Provider mode on again.");

        section(c, "My device ID (the provider ID others enter)");
        myId1 = body(c, "");
        myId1.setTextIsSelectable(true);
        button(c, "Copy my ID", true, v -> copyId());
        button(c, "Change my ID (cuts everyone off)", true, v -> confirmResetId());

        provStats = body(c, "");

        pendingTitle = section(c, "Waiting for your approval");
        pendingBox = new LinearLayout(ctx);
        pendingBox.setOrientation(LinearLayout.VERTICAL);
        c.addView(pendingBox);

        section(c, "Connected now");
        usersBox = new LinearLayout(ctx);
        usersBox.setOrientation(LinearLayout.VERTICAL);
        c.addView(usersBox);

        section(c, "Approved and blocked devices");
        approvedBox = new LinearLayout(ctx);
        approvedBox.setOrientation(LinearLayout.VERTICAL);
        c.addView(approvedBox);
    }

    private void buildClientCard(LinearLayout root) {
        LinearLayout c = card(root, "Client: use someone's internet",
                "Enter the provider's ID. The provider must approve this device once (send them your device ID from the Provider card). Your traffic is end-to-end encrypted to the provider.");
        clientProviderId = field(c, "Provider ID", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, mgr.clientProviderId());
        button(c, "Find providers", true, v -> findProviders());
        clientProxyPort = field(c, "Local proxy port", InputType.TYPE_CLASS_NUMBER, String.valueOf(mgr.clientProxyPort()));
        clientSwitch = new SwitchCompat(ctx);
        clientSwitch.setText("Client mode");
        clientSwitch.setTextColor(color(R.color.primary_text));
        c.addView(clientSwitch);
        clientSwitch.setOnClickListener(v -> onClientToggle());
        autoSw = new SwitchCompat(ctx);
        autoSw.setText("Connect automatically when the launcher opens");
        autoSw.setTextColor(color(R.color.primary_text));
        autoSw.setChecked(mgr.autoStartClient());
        autoSw.setOnClickListener(v -> mgr.setAutoStartClient(autoSw.isChecked()));
        c.addView(autoSw);
        routeSw = new SwitchCompat(ctx);
        routeSw.setText("Use SS Internet for Supersonic Client's own traffic");
        routeSw.setTextColor(color(R.color.primary_text));
        routeSw.setChecked(mgr.routeEnabled());
        routeSw.setOnClickListener(v -> mgr.setRouteEnabled(routeSw.isChecked()));
        c.addView(routeSw);
        body(c, "Downloads (Minecraft versions, assets) and browsing mods and addons go through the provider. YouTube, Google, your browser and other apps keep using your own internet. Minecraft's in-game multiplayer connections are not covered yet.");
        fallbackSw = new SwitchCompat(ctx);
        fallbackSw.setText("If the provider goes offline, use my own internet");
        fallbackSw.setTextColor(color(R.color.primary_text));
        fallbackSw.setChecked(mgr.fallbackToOwnInternet());
        fallbackSw.setOnClickListener(v -> mgr.setFallbackToOwnInternet(fallbackSw.isChecked()));
        c.addView(fallbackSw);
        body(c, "On: when the provider's connection fails, a red alert \"" + SsInternetManager.ALERT_TEXT + "\" shows for 16 seconds and Supersonic switches to your own internet (servers then see your IP) until the provider is back. Off: requests simply fail until it is back.");
        clientStatus = body(c, "");
        clientStats = body(c, "");
        button(c, "Speed test", true, v -> speedTest());
        clientHow = body(c, "");
    }

    // ------------------------------------------------------------------ actions

    private boolean saveRelay() {
        String host = relayHost.getText().toString().trim();
        int port = parseInt(relayPort, 8443);
        String pin = relayPin.getText().toString().trim();
        if (host.isEmpty() || host.contains(" ") || host.contains("/")) { toast("Enter a valid relay host name or IP."); return false; }
        if (port < 1 || port > 65535) { toast("Port must be 1 to 65535."); return false; }
        if (!pin.isEmpty() && !Identity.isValidId(pin)) { toast("The relay ID is not valid."); return false; }
        mgr.saveRelay(host, port, pin.isEmpty() ? "" : Identity.normalizeId(pin));
        return true;
    }

    private void saveFields() {
        if (mgr == null || relayHost == null) return;
        String host = relayHost.getText().toString().trim();
        String pin = relayPin.getText().toString().trim();
        int port = parseInt(relayPort, 8443);
        if (!host.contains(" ") && port >= 1 && port <= 65535 && (pin.isEmpty() || Identity.isValidId(pin))) {
            mgr.saveRelay(host, port, pin.isEmpty() ? "" : Identity.normalizeId(pin));
        }
        String country = provCountry.getText().toString().trim().toUpperCase(Locale.US);
        if (!country.matches("[A-Z]{2}")) country = "";
        mgr.saveProvider(provName.getText().toString().trim(), country, provListed.isChecked(), provOpen.isChecked(),
                Math.max(1, parseInt(provMax, 5)), Math.max(0, parseInt(provLimit, 0)), Math.max(0, parseInt(provCap, 0)));
        String pid = clientProviderId.getText().toString().trim();
        mgr.saveClient(Identity.isValidId(pid) ? Identity.normalizeId(pid) : pid, parseInt(clientProxyPort, 1080));
    }

    private void onProviderToggle() {
        if (!provSwitch.isChecked()) {
            PojavApplication.sExecutorService.execute(mgr::stopProvider);
            return;
        }
        if (!saveRelay()) { provSwitch.setChecked(false); return; }
        saveFields();
        provStarting = true;
        PojavApplication.sExecutorService.execute(() -> {
            try {
                mgr.startProvider();
            } catch (Exception e) {
                toast("Could not start: " + e.getMessage());
                Tools.runOnUiThread(() -> { if (provSwitch != null) provSwitch.setChecked(false); });
            } finally {
                provStarting = false;
            }
        });
    }

    private void onClientToggle() {
        if (!clientSwitch.isChecked()) {
            PojavApplication.sExecutorService.execute(mgr::stopClient);
            return;
        }
        if (!saveRelay()) { clientSwitch.setChecked(false); return; }
        saveFields();
        if (!Identity.isValidId(clientProviderId.getText().toString())) {
            toast("Enter a valid provider ID first.");
            clientSwitch.setChecked(false);
            return;
        }
        clientStarting = true;
        PojavApplication.sExecutorService.execute(() -> {
            try {
                mgr.startClient();
            } catch (Exception e) {
                toast("Could not start: " + e.getMessage());
                Tools.runOnUiThread(() -> { if (clientSwitch != null) clientSwitch.setChecked(false); });
            } finally {
                clientStarting = false;
            }
        });
    }

    private void findProviders() {
        if (!saveRelay()) return;
        PojavApplication.sExecutorService.execute(() -> {
            try {
                final List<RelayLink.ProviderEntry> list =
                        new RelayLink(mgr.relayHost(), mgr.relayPort(), mgr.relayPin(), mgr.identity()).listProviders();
                Tools.runOnUiThread(() -> showProviderList(list));
            } catch (Exception e) {
                toast("Could not reach the relay: " + e.getMessage());
            }
        });
    }

    private void showProviderList(final List<RelayLink.ProviderEntry> list) {
        if (!isAdded()) return;
        if (list.isEmpty()) { toast("No providers are listed right now."); return; }
        final String[] items = new String[list.size()];
        for (int i = 0; i < items.length; i++) {
            RelayLink.ProviderEntry e = list.get(i);
            items[i] = e.name + (e.country.isEmpty() ? "" : " (" + e.country + ")") + "  " + e.active + "/" + e.max + " users";
        }
        new AlertDialog.Builder(ctx).setTitle("Listed providers")
                .setItems(items, (d, which) -> clientProviderId.setText(Identity.pretty(list.get(which).id)))
                .setNegativeButton(android.R.string.cancel, null).show();
    }

    private void speedTest() {
        final ClientEngine c = mgr.client();
        if (c == null || c.state() != ClientEngine.State.CONNECTED) { toast("Connect first."); return; }
        toast("Testing...");
        PojavApplication.sExecutorService.execute(() -> {
            try {
                double bps = c.speedTest(4 * 1024 * 1024);
                toast(String.format(Locale.US, "Download through the tunnel: %s", rate(bps)));
            } catch (Exception e) {
                toast("Speed test failed: " + e.getMessage());
            }
        });
    }

    private void copyId() {
        try {
            String id = Identity.pretty(mgr.identity().id);
            ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("SS Internet ID", id));
            toast("ID copied");
        } catch (Exception e) {
            toast("Could not read the ID: " + e.getMessage());
        }
    }

    private void confirmResetId() {
        new AlertDialog.Builder(ctx).setTitle("Change my ID?")
                .setMessage("Provider and Client mode stop and this device gets a new ID. Everyone who has your old provider ID is cut off until you give them the new one.")
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Change", (d, w) -> PojavApplication.sExecutorService.execute(() -> {
                    mgr.resetIdentity();
                    toast("New ID created");
                })).show();
    }

    private void askLabelAndApprove(final String id) {
        final EditText input = new EditText(ctx);
        input.setHint("Name for this device (optional)");
        new AlertDialog.Builder(ctx).setTitle("Approve device?")
                .setMessage("Anyone with this device can use your internet connection and traffic quota, and the websites they visit will see your IP address.\n\n" + Identity.pretty(id))
                .setView(input)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton("Approve", (d, w) -> {
                    ProviderEngine p = mgr.provider();
                    if (p != null) p.approve(id, input.getText().toString().trim());
                    pendingSig = "";
                    approvedSig = "";
                }).show();
    }

    // ------------------------------------------------------------------ live refresh

    private void refresh() {
        if (!isAdded() || provStatus == null) return;
        try {
            myId1.setText(Identity.pretty(mgr.identity().id));
        } catch (Exception e) {
            myId1.setText("(no ID: " + e.getMessage() + ")");
        }
        refreshProvider();
        refreshClient();
    }

    private void refreshProvider() {
        ProviderEngine p = mgr.provider();
        if (!provStarting) provSwitch.setChecked(p != null);
        if (p == null) {
            provStatus.setText("Off. Nobody can use your internet.");
            provStats.setText("");
            pendingTitle.setVisibility(View.GONE);
            pendingBox.removeAllViews();
            usersBox.removeAllViews();
            approvedBox.removeAllViews();
            pendingSig = "";
            approvedSig = "";
            return;
        }
        provStatus.setText(stateText(p.state(), p.detail()));
        provStats.setText(String.format(Locale.US, "Users connected: %d\nSpeed now: down %s, up %s (as seen by the users)\nData this run: %s   All time: %s",
                p.connectedCount(), rate(p.totalDownRate()), rate(p.totalUpRate()),
                SupersonicUi.formatBytes(p.sessionBytes()), SupersonicUi.formatBytes(p.lifetimeBytes())));

        // pending requests (rebuilt only when the set changes, so buttons stay tappable)
        List<ApprovalStore.Pending> pend = p.pending();
        StringBuilder sig = new StringBuilder();
        for (ApprovalStore.Pending x : pend) sig.append(x.id);
        if (!sig.toString().equals(pendingSig)) {
            pendingSig = sig.toString();
            pendingBox.removeAllViews();
            for (final ApprovalStore.Pending x : pend) {
                pendingBox.addView(deviceRow(x.id, "wants to connect",
                        "Approve", v -> askLabelAndApprove(x.id),
                        "Block", v -> { p.deny(x.id); pendingSig = ""; approvedSig = ""; }));
            }
        }
        pendingTitle.setVisibility(pend.isEmpty() ? View.GONE : View.VISIBLE);

        // connected now: plain text, rebuilt each second
        usersBox.removeAllViews();
        List<ProviderEngine.ClientInfo> users = p.clients();
        if (users.isEmpty()) body(usersBox, "Nobody is connected.");
        for (ProviderEngine.ClientInfo u : users) {
            body(usersBox, String.format(Locale.US, "%s%s\n   down %s  up %s  ping %s  %d connections",
                    u.label.isEmpty() ? "" : u.label + "  ", Identity.pretty(u.id).substring(0, 14),
                    SupersonicUi.formatBytes(u.downBytes), SupersonicUi.formatBytes(u.upBytes),
                    u.rttMillis < 0 ? "-" : u.rttMillis + " ms", u.streams));
        }

        // approved + blocked
        Map<String, String> approved = p.approvals().approvedMap();
        List<String> blocked = p.approvals().blockedList();
        StringBuilder as = new StringBuilder();
        for (Map.Entry<String, String> e : approved.entrySet()) as.append('A').append(e.getKey());
        for (String b : blocked) as.append('B').append(b);
        if (!as.toString().equals(approvedSig)) {
            approvedSig = as.toString();
            approvedBox.removeAllViews();
            if (approved.isEmpty() && blocked.isEmpty()) body(approvedBox, "No devices yet.");
            for (final Map.Entry<String, String> e : approved.entrySet()) {
                approvedBox.addView(deviceRow(e.getKey(), e.getValue().isEmpty() ? "approved" : e.getValue(),
                        "Remove", v -> { p.revoke(e.getKey()); approvedSig = ""; }, null, null));
            }
            for (final String b : blocked) {
                approvedBox.addView(deviceRow(b, "blocked", "Unblock", v -> { p.revoke(b); approvedSig = ""; }, null, null));
            }
        }
    }

    private void refreshClient() {
        ClientEngine c = mgr.client();
        if (!clientStarting) clientSwitch.setChecked(c != null);
        if (c == null) {
            clientStatus.setText("Off.");
            clientStats.setText(String.format(Locale.US, "All time: down %s, up %s",
                    SupersonicUi.formatBytes(mgr.clientLifetimeDown()), SupersonicUi.formatBytes(mgr.clientLifetimeUp())));
            clientHow.setText("");
            return;
        }
        clientStatus.setText(stateText(c.state(), c.detail()));
        boolean up = c.state() == ClientEngine.State.CONNECTED;
        clientStats.setText(String.format(Locale.US, "Ping: %s\nSpeed now: down %s, up %s\nData this run: down %s, up %s   (all time: down %s, up %s)\nOpen connections: %d",
                !up || c.rttMillis() < 0 ? "-" : c.rttMillis() + " ms", rate(c.downRate()), rate(c.upRate()),
                SupersonicUi.formatBytes(c.downBytes()), SupersonicUi.formatBytes(c.upBytes()),
                SupersonicUi.formatBytes(mgr.clientLifetimeDown() + c.downBytes()), SupersonicUi.formatBytes(mgr.clientLifetimeUp() + c.upBytes()),
                c.openConnections()));
        clientHow.setText(String.format(Locale.US,
                "Local proxy: 127.0.0.1:%d (HTTP and SOCKS5 on the same port).\nWi-Fi settings > this network > Proxy > Manual > host 127.0.0.1, port %d makes the browser and apps that follow the system proxy use this connection. Apps that ignore proxy settings are not covered yet.",
                c.socksPort(), c.socksPort()));
    }

    private static String stateText(Object state, String detail) {
        String s = state.toString().replace('_', ' ').toLowerCase(Locale.US);
        return s.substring(0, 1).toUpperCase(Locale.US) + s.substring(1) + (detail == null || detail.isEmpty() || detail.equals(s) ? "" : ": " + detail);
    }

    private static String rate(double bytesPerSec) {
        double bits = bytesPerSec * 8;
        if (bits < 1_000_000) return String.format(Locale.US, "%.0f kbit/s", bits / 1000);
        return String.format(Locale.US, "%.1f Mbit/s", bits / 1_000_000);
    }

    // ------------------------------------------------------------------ view helpers

    private View deviceRow(String id, String note, String label1, View.OnClickListener a1, @Nullable String label2, @Nullable View.OnClickListener a2) {
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, dp(6), 0, dp(6));
        TextView t = new TextView(ctx, null, 0, R.style.SS_Body);
        t.setText(Identity.pretty(id) + "\n" + note);
        t.setTextIsSelectable(true);
        row.addView(t);
        LinearLayout buttons = new LinearLayout(ctx);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        Button b1 = button(buttons, label1, false, a1);
        ((LinearLayout.LayoutParams) b1.getLayoutParams()).setMarginEnd(dp(8));
        if (label2 != null) button(buttons, label2, true, a2);
        row.addView(buttons);
        return row;
    }

    private LinearLayout card(LinearLayout root, String title, String subtitle) {
        LinearLayout c = new LinearLayout(ctx);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setBackgroundResource(R.drawable.bg_supersonic_card);
        c.setPadding(dp(14), dp(12), dp(14), dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(10);
        root.addView(c, lp);
        TextView h = new TextView(ctx, null, 0, R.style.SS_Heading);
        h.setText(title);
        c.addView(h);
        body(c, subtitle);
        return c;
    }

    private TextView body(LinearLayout parent, String text) {
        TextView t = new TextView(ctx, null, 0, R.style.SS_Body);
        t.setText(text);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(6);
        parent.addView(t, lp);
        return t;
    }

    private TextView section(LinearLayout parent, String text) {
        TextView t = new TextView(ctx, null, 0, R.style.SS_Section);
        t.setText(text);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(14);
        parent.addView(t, lp);
        return t;
    }

    private EditText field(LinearLayout parent, String hint, int inputType, String value) {
        EditText e = new EditText(ctx);
        e.setHint(hint);
        e.setInputType(inputType);
        e.setText(value);
        e.setSingleLine(true);
        e.setTextSize(13);
        e.setTextColor(color(R.color.primary_text));
        e.setHintTextColor(color(R.color.secondary_text));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(6);
        parent.addView(e, lp);
        return e;
    }

    private Button button(ViewGroup parent, String label, boolean outline, View.OnClickListener l) {
        Button b = new Button(ctx, null, 0, outline ? R.style.SS_ButtonOutline : R.style.SS_Button);
        b.setText(label);
        b.setOnClickListener(l);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(8);
        parent.addView(b, lp);
        return b;
    }

    private int color(int res) { return ContextCompat.getColor(ctx, res); }

    private int dp(float v) { return SupersonicUi.dp(requireContext(), v); }

    private void toast(final String m) {
        Tools.runOnUiThread(() -> { if (isAdded()) Toast.makeText(ctx, m, Toast.LENGTH_LONG).show(); });
    }

    private static int parseInt(EditText e, int def) {
        try { return Integer.parseInt(e.getText().toString().trim()); } catch (NumberFormatException ex) { return def; }
    }
}
