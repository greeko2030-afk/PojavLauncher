package com.supersonic.ssinternet.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The provider's own decision list. Nobody connects without being on it:
 * an unknown device only creates a pending request that the provider must approve by hand.
 */
public final class ApprovalStore {
    public enum State { APPROVED, BLOCKED, UNKNOWN }

    public static final class Pending {
        public final String id;
        public final long since;
        Pending(String id, long since) { this.id = id; this.since = since; }
    }

    private static final long PENDING_TTL_MS = 15 * 60 * 1000L;
    private static final int MAX_PENDING = 50;
    private final File file;
    private final Map<String, String> approved = new LinkedHashMap<>();
    private final Map<String, String> blocked = new LinkedHashMap<>();
    private final Map<String, Long> pending = new LinkedHashMap<>();

    public ApprovalStore(File file) {
        this.file = file;
        load();
    }

    private synchronized void load() {
        if (!file.isFile()) return;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(file), Charset.forName("UTF-8")))) {
            String line;
            while ((line = r.readLine()) != null) {
                String[] p = line.split("\t", 3);
                if (p.length < 2 || !Identity.isValidId(p[1])) continue;
                String label = p.length == 3 ? Codec.urlDecode(p[2]) : "";
                if (p[0].equals("A")) approved.put(p[1], label);
                else if (p[0].equals("B")) blocked.put(p[1], label);
            }
        } catch (IOException ignored) {
        }
    }

    private synchronized void save() {
        File tmp = new File(file.getPath() + ".tmp");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(tmp), Charset.forName("UTF-8"))) {
            for (Map.Entry<String, String> e : approved.entrySet()) w.write("A\t" + e.getKey() + "\t" + Codec.urlEncode(e.getValue()) + "\n");
            for (Map.Entry<String, String> e : blocked.entrySet()) w.write("B\t" + e.getKey() + "\t" + Codec.urlEncode(e.getValue()) + "\n");
        } catch (IOException e) {
            return;
        }
        tmp.renameTo(file);
    }

    public synchronized State state(String id) {
        if (approved.containsKey(id)) return State.APPROVED;
        if (blocked.containsKey(id)) return State.BLOCKED;
        return State.UNKNOWN;
    }

    /** @return true if this is a new request (so the provider should be notified). */
    public synchronized boolean addPending(String id) {
        long now = System.currentTimeMillis();
        expire(now);
        if (pending.containsKey(id)) {
            pending.put(id, now);
            return false;
        }
        if (pending.size() >= MAX_PENDING) return false; // flood protection
        pending.put(id, now);
        return true;
    }

    private void expire(long now) { // Collection.removeIf needs Android 24
        for (java.util.Iterator<Long> it = pending.values().iterator(); it.hasNext(); ) {
            if (now - it.next() > PENDING_TTL_MS) it.remove();
        }
    }

    public synchronized List<Pending> pending() {
        long now = System.currentTimeMillis();
        expire(now);
        List<Pending> out = new ArrayList<>();
        for (Map.Entry<String, Long> e : pending.entrySet()) out.add(new Pending(e.getKey(), e.getValue()));
        return out;
    }

    public synchronized void approve(String id, String label) {
        pending.remove(id);
        blocked.remove(id);
        approved.put(id, label == null ? "" : label);
        save();
    }

    public synchronized void block(String id) {
        pending.remove(id);
        approved.remove(id);
        blocked.put(id, "");
        save();
    }

    /** Removes a device from both lists; it becomes unknown again (and may ask again). */
    public synchronized void forget(String id) {
        pending.remove(id);
        approved.remove(id);
        blocked.remove(id);
        save();
    }

    public synchronized Map<String, String> approvedMap() { return new LinkedHashMap<>(approved); }

    public synchronized List<String> blockedList() { return new ArrayList<>(blocked.keySet()); }
}
