package net.kdt.pojavlaunch.supersonic;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;

import net.kdt.pojavlaunch.R;
import net.kdt.pojavlaunch.prefs.LauncherPreferences;
import net.kdt.pojavlaunch.utils.JREUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * The dialog of the JVM arguments (Settings > Minecraft). Each argument is one row: a box that turns it on or off,
 * the argument itself (edit it in place) and a button that deletes it. A button adds a new row.
 *
 * Nothing is saved until Save is pressed. Save checks every argument that is on in the same way as the launcher
 * will read it (see JvmArgsStore), and a row with a problem is marked, so an argument that would have no effect
 * is not saved without a word. What is saved is what the launcher uses at the next start of the game.
 */
public final class JvmArgsDialog {
    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final Runnable mOnSaved;
    private final List<Row> mRows = new ArrayList<>();

    private ScrollView mScroll;
    private LinearLayout mContainer;
    private TextView mEmptyHint;
    private TextView mStatus;
    private AlertDialog mDialog;

    private static final class Row {
        final View view;
        final CheckBox enabled;
        final EditText arg;

        Row(View view, CheckBox enabled, EditText arg) {
            this.view = view;
            this.enabled = enabled;
            this.arg = arg;
        }
    }

    private JvmArgsDialog(Context context, SharedPreferences prefs, Runnable onSaved) {
        mContext = context;
        mPrefs = prefs;
        mOnSaved = onSaved;
    }

    /**
     * Shows the dialog.
     *
     * @param prefs   the preferences of the launcher
     * @param onSaved called after the list was saved, for example to refresh the text of the setting
     */
    public static void show(Context context, SharedPreferences prefs, Runnable onSaved) {
        new JvmArgsDialog(context, prefs, onSaved).open();
    }

    private void open() {
        View content = LayoutInflater.from(mContext).inflate(R.layout.dialog_jvm_args, null);
        mScroll = content.findViewById(R.id.jvm_args_scroll);
        mContainer = content.findViewById(R.id.jvm_args_container);
        mEmptyHint = content.findViewById(R.id.jvm_args_empty);
        mStatus = content.findViewById(R.id.jvm_args_status);
        content.findViewById(R.id.jvm_args_add).setOnClickListener(v -> addRow(new JvmArgsStore.Item("", true), true));

        for (JvmArgsStore.Item item : JvmArgsStore.load(mPrefs)) addRow(item, false);
        refreshEmptyHint();

        mDialog = new AlertDialog.Builder(mContext)
                .setTitle("JVM arguments")
                .setView(content)
                .setPositiveButton("Save", null) // set below: a click must not close the dialog when there is a problem
                .setNegativeButton("Cancel", null)
                .create();
        mDialog.setOnShowListener(dialog -> {
            // Rows are added later, so the dialog may have been built without an input field.
            // Then the keyboard would not open for a row that was added afterwards.
            if (mDialog.getWindow() != null) {
                mDialog.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_ALT_FOCUSABLE_IM);
                mDialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
            }
            mDialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> save());
        });
        mDialog.show();
    }

    private void addRow(JvmArgsStore.Item item, boolean focus) {
        View view = LayoutInflater.from(mContext).inflate(R.layout.item_jvm_arg, mContainer, false);
        CheckBox enabled = view.findViewById(R.id.jvm_arg_enabled);
        EditText arg = view.findViewById(R.id.jvm_arg_text);
        ImageButton delete = view.findViewById(R.id.jvm_arg_delete);
        final Row row = new Row(view, enabled, arg);

        enabled.setChecked(item.enabled);
        arg.setText(item.arg);
        arg.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            @Override
            public void afterTextChanged(Editable s) {
                // The message is about the text that was typed before
                arg.setError(null);
                mStatus.setVisibility(View.GONE);
            }
        });
        delete.setOnClickListener(v -> {
            mContainer.removeView(row.view);
            mRows.remove(row);
            mStatus.setVisibility(View.GONE);
            refreshEmptyHint();
        });

        mRows.add(row);
        mContainer.addView(view);
        refreshEmptyHint();
        if (focus) {
            arg.post(() -> {
                mScroll.smoothScrollTo(0, mContainer.getBottom());
                arg.requestFocus();
                InputMethodManager imm = (InputMethodManager) mContext.getSystemService(Context.INPUT_METHOD_SERVICE);
                if (imm != null) imm.showSoftInput(arg, InputMethodManager.SHOW_IMPLICIT);
            });
        }
    }

    private void refreshEmptyHint() {
        mEmptyHint.setVisibility(mRows.isEmpty() ? View.VISIBLE : View.GONE);
    }

    private void save() {
        // A row that was left empty is just dropped
        List<Row> checkedRows = new ArrayList<>();
        List<JvmArgsStore.Item> items = new ArrayList<>();
        for (Row row : mRows) {
            row.arg.setError(null);
            String text = row.arg.getText().toString().trim();
            if (text.isEmpty()) continue;
            checkedRows.add(row);
            items.add(new JvmArgsStore.Item(text, row.enabled.isChecked()));
        }

        List<JvmArgsStore.Problem> problems = JvmArgsStore.validate(items, JREUtils::parseJavaArguments);
        if (!problems.isEmpty()) {
            for (JvmArgsStore.Problem problem : problems) {
                checkedRows.get(problem.index).arg.setError(problem.message);
            }
            JvmArgsStore.Problem first = problems.get(0);
            mStatus.setText((problems.size() == 1 ? "1 argument needs a fix: " : problems.size() + " arguments need a fix. First: ")
                    + first.message);
            mStatus.setVisibility(View.VISIBLE);
            checkedRows.get(first.index).arg.requestFocus();
            return; // the dialog stays open
        }

        JvmArgsStore.save(mPrefs, items);
        // The launcher keeps the values of the settings in memory. Read them again.
        LauncherPreferences.loadPreferences(mContext);
        mOnSaved.run();
        mDialog.dismiss();
    }
}
