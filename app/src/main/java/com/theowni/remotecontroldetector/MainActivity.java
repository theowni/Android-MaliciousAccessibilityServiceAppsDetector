package com.theowni.remotecontroldetector;

import android.os.Bundle;
import android.util.Log;

import com.theowni.remotecontroldetector.utils.RemoteDetector;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Set;
import com.google.common.collect.Sets;

public class MainActivity extends BaseSecureActivity {
    String logTag = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        runChecks();
    }

    void runChecks() {
        InputStream configFileStream = getResources().openRawResource(R.raw.appconfigs);

        RemoteDetector remoteDetector = null;
        remoteDetector = new RemoteDetector(configFileStream, getApplicationContext());

        Log.d(logTag, "Lists applications found in blocked lists - configurable");
        Set<String> suspiciousAppsInstalled = remoteDetector.getSuspiciousApplicationsInstalled();
        Log.d(logTag, "Lists suspicious AccessibilityServices installed - configurable");
        Set<String> appsWithSuspiciousASvcsInstalled = remoteDetector.getSuspiciousAccessibilityServicesInstalled();
        Log.d(logTag, "Lists suspicious AccessibilityServices enabled - configurable");
        Set<String> appsWithSuspiciousASvcsEnabled = remoteDetector.getSuspiciousAccessibilityServicesEnabled();
        Log.d(logTag, "Lists applications that currently use suspicious ports - configurable");
        Set<String> appsWithSuspiciousPortsInUse = remoteDetector.getAppsWithSuspiciousPortsInUse();
        Log.d(logTag, "Lists applications that use suspicious permissions - based on hardcoded checks");
        Set<String> appsWithSuspiciousASvcsSettings = remoteDetector.getAccessibilityServicesWithSuspiciousSettingsInstalled();
        Log.d(logTag, "Lists applications that were installed in 15 minutes offset to suspicious app installation time - based on hardcoded checks");
        Set<String> appsWithCorrelatedInstallTimesWithSuspiciousApps = remoteDetector.getAppsWithCorrelatedInstallTimesWithSuspiciousApps();
        Log.d(logTag, "Lists applications that were installed in last 15 minutes - based on hardcoded checks");
        Set<String> appsInstalledInLastQuarter = remoteDetector.getAvailabilityServicesInstalledInLastQuarter();

        if (Sets.intersection(
                appsWithSuspiciousASvcsEnabled,
                appsWithSuspiciousPortsInUse)
                .size() > 0)
            Log.d(logTag, "Device may be controlled or viewed by malicious apps - very high possibility");

        if (Sets.intersection(
                Sets.intersection(appsWithSuspiciousASvcsEnabled, appsInstalledInLastQuarter),
                appsWithCorrelatedInstallTimesWithSuspiciousApps).size() > 0)
            Log.d(logTag, "Device may be controlled or viewed by malicious apps - high possibility");

        if (Sets.intersection(
                appsWithSuspiciousASvcsEnabled,
                appsWithSuspiciousASvcsSettings)
                .size() > 0)
            Log.d(logTag, "Device may be controlled or viewed by malicious apps - medium possibility");

        if (appsWithSuspiciousASvcsEnabled.size() > 0)
            Log.d(logTag, "Device may be controlled or viewed by malicious apps - medium possibility");

        if (Sets.intersection(
                remoteDetector.getAccessibilityServiceIDsEnabled(),
                appsWithSuspiciousASvcsSettings)
                .size() > 0)
            Log.d(logTag, "Device may be controlled or viewed by malicious apps - medium possibility");

        if (Sets.intersection(
                appsWithSuspiciousASvcsInstalled,
                appsWithSuspiciousASvcsSettings)
                .size() != 0)
            Log.d(logTag, "Device may be controlled or viewed by malicious apps - low/medium possibility");
    }
}