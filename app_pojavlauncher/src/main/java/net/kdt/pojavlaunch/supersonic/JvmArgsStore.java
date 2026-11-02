package net.kdt.pojavlaunch.supersonic;

import android.content.SharedPreferences;

import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The JVM arguments of the game as a list: every argument is one entry that can be added, edited, deleted and
 * turned on or off.
 *
 * The launcher reads its Java arguments from one text, the preference {@link #PREF_ARGS}. That text stays the only
 * thing that the launcher uses, so the list works everywhere without any other change: saving the list writes the
 * arguments that are ON into that text, one after another. The whole list, with the arguments that are OFF, is
 * kept in a second preference ({@link #PREF_LIST}). When the text was changed somewhere else (an older version, a
 * reset of the settings), the text wins and the list is made from it again.
 *
 * The launcher does not use the text as it is. It splits it with its own parser (JREUtils.parseJavaArguments),
 * which only knows some kinds of arguments, drops some of them, and removes the memory and processor arguments
 * later. So an argument that is written here is checked in the same way, and an argument that would have no effect
 * is refused with the reason, instead of being lost silently.
 */
public final class JvmArgsStore {
    private JvmArgsStore() {}

    /** The text that the launcher reads. */
    public static final String PREF_ARGS = "javaArgs";
    /** The list with the arguments that are on and off, as JSON. */
    public static final String PREF_LIST = "supersonic_jvm_args";

    /** The kinds of arguments that the parser of the launcher can split from each other. */
    private static final String[] SUPPORTED_PREFIXES = {"-XX:", "-X", "-D", "--", "-javaagent:", "-verbose"};

    /** JREUtils.launchJavaVM removes every argument that starts with one of these, so they would have no effect. */
    static final String[] IGNORED_PREFIXES = {
            "-Xms", "-Xmx", "-d32", "-d64", "-Xint",
            "-XX:+UseTransparentHugePages", "-XX:+UseLargePagesInMetaspace", "-XX:+UseLargePages",
            "-Dorg.lwjgl.opengl.libname", "-Dorg.lwjgl.freetype.libname", "-XX:ActiveProcessorCount"
    };

    private static final Gson GSON = new Gson();

    /** One argument and whether it is used. */
    public static final class Item {
        public String arg;
        public boolean enabled;

        public Item() {}

        public Item(String arg, boolean enabled) {
            this.arg = arg;
            this.enabled = enabled;
        }
    }

    /** Splits a text into arguments the way the launcher does. It is JREUtils::parseJavaArguments. */
    public interface Parser {
        List<String> parse(String arguments);
    }

    /** Something that is wrong with the argument in one row. */
    public static final class Problem {
        /** The index in the list that was checked. */
        public final int index;
        public final String message;

        Problem(int index, String message) {
            this.index = index;
            this.message = message;
        }
    }

    // ------------------------------------------------------------------ loading and saving

    /**
     * The list for the screen. The saved list is used while it still gives the text that the launcher reads.
     * Otherwise the list is made from that text, with every argument on.
     */
    public static List<Item> load(SharedPreferences prefs) {
        String text = prefs.getString(PREF_ARGS, "");
        List<Item> saved = readList(prefs.getString(PREF_LIST, null));
        if (saved != null && normalize(join(saved)).equals(normalize(text))) return saved;
        return fromText(text);
    }

    /** Saves the list, and writes the arguments that are on into the text that the launcher reads. */
    public static void save(SharedPreferences prefs, List<Item> items) {
        List<Item> clean = new ArrayList<>();
        for (Item item : items) {
            String arg = item.arg == null ? "" : item.arg.trim();
            if (!arg.isEmpty()) clean.add(new Item(arg, item.enabled));
        }
        prefs.edit()
                .putString(PREF_LIST, GSON.toJson(clean))
                .putString(PREF_ARGS, join(clean))
                .apply();
    }

    /** The text for the launcher: the arguments that are on, one after another. */
    public static String join(List<Item> items) {
        StringBuilder out = new StringBuilder();
        for (Item item : items) {
            if (!item.enabled || item.arg == null) continue;
            String arg = item.arg.trim();
            if (arg.isEmpty()) continue;
            if (out.length() > 0) out.append(' ');
            out.append(arg);
        }
        return out.toString();
    }

    /** The arguments of an older text (or of another place that changed it): all on. */
    static List<Item> fromText(String text) {
        List<Item> items = new ArrayList<>();
        if (text == null) return items;
        for (String token : text.trim().split("\\s+")) {
            if (!token.isEmpty()) items.add(new Item(token, true));
        }
        return items;
    }

    private static String normalize(String text) {
        StringBuilder out = new StringBuilder();
        for (Item item : fromText(text)) {
            if (out.length() > 0) out.append(' ');
            out.append(item.arg);
        }
        return out.toString();
    }

    private static List<Item> readList(String json) {
        if (json == null || json.isEmpty()) return null;
        try {
            Item[] array = GSON.fromJson(json, Item[].class);
            if (array == null) return null;
            List<Item> list = new ArrayList<>();
            for (Item item : array) {
                if (item == null || item.arg == null) return null;
                list.add(new Item(item.arg, item.enabled));
            }
            return list;
        } catch (RuntimeException e) {
            return null;
        }
    }

    // ------------------------------------------------------------------ checking

    /**
     * Checks the list the way the launcher will use it. An argument that is off is never used, so it is not checked.
     *
     * @param parser the real parser of the launcher
     * @return what is wrong, for the arguments that are on, ordered by their place in the list
     */
    public static List<Problem> validate(List<Item> items, Parser parser) {
        List<Problem> problems = new ArrayList<>();
        Set<Integer> wrong = new HashSet<>();
        Map<String, Integer> firstRow = new HashMap<>();

        for (int i = 0; i < items.size(); i++) {
            Item item = items.get(i);
            if (!item.enabled) continue;
            String arg = item.arg == null ? "" : item.arg.trim();
            String message = checkOne(arg);
            if (message == null) {
                Integer first = firstRow.get(arg);
                if (first != null) {
                    message = "The same argument is already in row " + (first + 1) + ". Only one of them would be used.";
                } else {
                    firstRow.put(arg, i);
                }
            }
            if (message != null) {
                problems.add(new Problem(i, message));
                wrong.add(i);
            }
        }

        // The launcher reads all arguments from one text. Check that it reads exactly what is written here:
        // for example a ',' can join an argument to the one before it.
        List<Integer> toRead = new ArrayList<>();
        StringBuilder line = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            Item item = items.get(i);
            if (!item.enabled || wrong.contains(i)) continue;
            toRead.add(i);
            if (line.length() > 0) line.append(' ');
            line.append(item.arg.trim());
        }
        if (!toRead.isEmpty()) {
            Map<String, Integer> read = new HashMap<>();
            for (String arg : parser.parse(line.toString())) {
                Integer count = read.get(arg);
                read.put(arg, count == null ? 1 : count + 1);
            }
            for (int index : toRead) {
                String arg = items.get(index).arg.trim();
                Integer count = read.get(arg);
                if (count != null && count > 0) {
                    read.put(arg, count - 1);
                } else {
                    problems.add(new Problem(index, "The launcher would not read this argument as written. "
                            + "It can have only one '=' (except --add-opens, --add-exports and --add-reads), "
                            + "and a ',' can join it to another argument."));
                }
            }
        }

        Collections.sort(problems, new Comparator<Problem>() {
            @Override
            public int compare(Problem a, Problem b) {
                return a.index - b.index;
            }
        });
        return problems;
    }

    /** @return what is wrong with one argument on its own, or null */
    private static String checkOne(String arg) {
        if (arg.isEmpty()) return "This row is empty. Type an argument or delete the row.";
        for (int i = 0; i < arg.length(); i++) {
            if (Character.isWhitespace(arg.charAt(i))) {
                return "An argument cannot contain spaces. Put each argument in its own row.";
            }
        }
        String ignored = ignoredReason(arg);
        if (ignored != null) return ignored;
        for (String prefix : SUPPORTED_PREFIXES) {
            if (arg.startsWith(prefix)) return null;
        }
        return "The launcher cannot use this argument. It must start with -XX:, -X, -D, --, -javaagent: or -verbose.";
    }

    /** @return why the launcher removes this argument, or null when it keeps it */
    static String ignoredReason(String arg) {
        for (String prefix : IGNORED_PREFIXES) {
            if (!arg.startsWith(prefix)) continue;
            if (prefix.equals("-Xms") || prefix.equals("-Xmx")) {
                return "The memory is set with the RAM setting, so the launcher ignores -Xms and -Xmx.";
            }
            if (prefix.equals("-XX:ActiveProcessorCount")) {
                return "The launcher sets the number of processors itself, so it ignores this argument.";
            }
            return "The launcher removes this argument before the game starts, so it has no effect.";
        }
        return null;
    }

    /** A short text for the setting, for example "3 arguments, 2 on". */
    public static String summary(List<Item> items) {
        if (items.isEmpty()) return "No arguments. Tap to add one.";
        int on = 0;
        for (Item item : items) {
            if (item.enabled) on++;
        }
        return items.size() + (items.size() == 1 ? " argument" : " arguments") + ", " + on
                + " on. Tap to add, edit or delete.";
    }
}
