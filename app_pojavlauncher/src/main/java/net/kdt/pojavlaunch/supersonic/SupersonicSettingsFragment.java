package net.kdt.pojavlaunch.supersonic;

import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import net.kdt.pojavlaunch.R;
import net.kdt.pojavlaunch.prefs.screens.LauncherPreferenceControlFragment;
import net.kdt.pojavlaunch.prefs.screens.LauncherPreferenceExperimentalFragment;
import net.kdt.pojavlaunch.prefs.screens.LauncherPreferenceFragment;
import net.kdt.pojavlaunch.prefs.screens.LauncherPreferenceJavaFragment;
import net.kdt.pojavlaunch.prefs.screens.LauncherPreferenceMiscellaneousFragment;
import net.kdt.pojavlaunch.prefs.screens.LauncherPreferenceVideoFragment;

/**
 * Settings screen with PC-style tabs. Every tab shows real Android settings.
 */
public class SupersonicSettingsFragment extends Fragment {
    public static final String TAG = "SupersonicSettingsFragment";

    private static final String[] TABS = {"General", "Performance", "Minecraft", "Controls", "Launcher", "Privacy", "SS Internet", "Advanced"};
    private static final String STATE_TAB = "tab";
    private int mTab = 0;

    public SupersonicSettingsFragment() {
        super(R.layout.fragment_supersonic_settings);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        if (savedInstanceState != null) mTab = savedInstanceState.getInt(STATE_TAB, 0);
        LinearLayout tabs = view.findViewById(R.id.settings_tabs);
        SupersonicUi.buildChips(tabs, TABS, mTab, index -> {
            mTab = index;
            show(index);
        });
        if (savedInstanceState == null) show(mTab);
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putInt(STATE_TAB, mTab);
    }

    private void show(int index) {
        Fragment fragment;
        switch (index) {
            case 1: fragment = new LauncherPreferenceVideoFragment(); break;
            case 2: fragment = new LauncherPreferenceJavaFragment(); break;
            case 3: fragment = new LauncherPreferenceControlFragment(); break;
            case 4: fragment = new LauncherPreferenceMiscellaneousFragment(); break;
            case 5: fragment = new SupersonicPrivacyFragment(); break;
            case 6: fragment = new net.kdt.pojavlaunch.supersonic.ssinternet.SsInternetFragment(); break;
            case 7: fragment = new LauncherPreferenceExperimentalFragment(); break;
            default: fragment = new LauncherPreferenceFragment();
        }
        getChildFragmentManager().beginTransaction()
                .replace(R.id.settings_container, fragment)
                .commit();
    }
}
