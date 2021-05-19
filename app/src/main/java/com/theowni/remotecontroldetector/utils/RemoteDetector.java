package com.theowni.remotecontroldetector.utils;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.os.Build;
import android.util.Log;
import android.view.accessibility.AccessibilityManager;

import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static android.accessibilityservice.AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES;
import static android.accessibilityservice.AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT;
import static android.accessibilityservice.AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;
import static android.view.accessibility.AccessibilityEvent.TYPE_VIEW_FOCUSED;
import static android.view.accessibility.AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED;
import static android.view.accessibility.AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED;

public class RemoteDetector {
    public AppDetectionConfig[] appDetectionConfigs;
    public Context mContext;
    String logTag = "RemoteDetector";
    String[] suspiciousPermissions = {"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.REQUEST_DELETE_PACKAGES",
            "android.permission.INJECT_EVENTS", "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT", "android.permission.INSTALL_PACKAGES", "android.permission.KILL_BACKGROUND_PROCESSES", "android.permission.sec.MDM_REMOTE_CONTROL", "android.permission.FOREGROUND_SERVICE", "android.permission.RECEIVE_BOOT_COMPLETED"};

    public RemoteDetector(InputStream configFileStream, Context context) {
        mContext = context;
        loadConfig(configFileStream);
    }

    /**
     * Method is used to obtain list of package names based on
     * configurable AppDetectionConfigs.
     * In Android 11 and higher may require to use QUERY_ALL_PACKAGES permissions.
     * @return Set<String> This returns set of package names.
     */
    public Set<String> getSuspiciousApplicationsInstalled() {
        Set<String> retApps = new HashSet<>();
        PackageManager pm = mContext.getPackageManager();

        for (AppDetectionConfig appConfig : appDetectionConfigs) {
            for (String packageName : appConfig.appPackageNames) {
                try {
                    pm.getPackageInfo(packageName, 0);
                    Log.d(logTag, "Suspicious packageName installation detected - " + packageName);
                    retApps.add(packageName);
                } catch (PackageManager.NameNotFoundException e) {
                    // pass Exception, packageName not found
                }
            }
        }

        return retApps;
    }

    /**
     * Method checks if the application was installed by
     * packages configured via AppDetectionConfigs.
     * Works more effective on Android 11 and higher.
     * @return boolean This returns boolean value.
     */
    boolean isInstalledByKnownDangerousApp(String packageName) {
        PackageManager pm = mContext.getPackageManager();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R){
            try {
                InstallSourceInfo installSourceInfo = pm.getInstallSourceInfo(packageName);

                for (AppDetectionConfig appConfig : appDetectionConfigs)
                    if (appConfig.appPackageNames.contains(installSourceInfo.getInitiatingPackageName()) ||
                            appConfig.appPackageNames.contains(installSourceInfo.getOriginatingPackageName()))
                        return true;
            } catch (PackageManager.NameNotFoundException e) {
                // pass Exception, packageName not found
            }
        } else {
            String installerPackageName = pm.getInstallerPackageName(packageName);

            for (AppDetectionConfig appConfig : appDetectionConfigs)
                if (appConfig.appPackageNames.contains(installerPackageName))
                    return true;
        }

        return false;
    }

    /**
     * Method checks if the application was installed by
     * application that uses suspicious permissions configured via suspiciousPermissions attribute.
     * It works more effective on Android 11 and higher as it uses getInitiatingPackageName.
     * @return boolean This returns boolean value.
     */
    boolean isInstalledByAppWithSuspiciousPermissions(String packageName) {
        PackageManager pm = mContext.getPackageManager();
        String installerPackageName = null;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R){
            try {
                InstallSourceInfo installSourceInfo = pm.getInstallSourceInfo(packageName);
                installerPackageName = installSourceInfo.getInitiatingPackageName();
            } catch (PackageManager.NameNotFoundException e) {
                // pass Exception, packageName not found
            }
        } else
            installerPackageName = pm.getInstallerPackageName(packageName);

        if (installerPackageName == null)
            return false;

        PackageInfo packageInfo = null;
        try {
            packageInfo = pm.getPackageInfo(installerPackageName, PackageManager.GET_PERMISSIONS);
        } catch (PackageManager.NameNotFoundException e) {
            // pass Exception, packageName not found
        }

        if (packageInfo == null)
            return false;

        if ((packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0)
            return false;

        int count = 0;
        if (packageInfo.requestedPermissions != null) {
            for (String perm : packageInfo.requestedPermissions){
                for (String suspPerm : suspiciousPermissions) {
                    if (perm.equals(suspPerm)) count++;
                }
            }
        }

        if (packageInfo.permissions != null) {
            for (PermissionInfo perm : packageInfo.permissions) {
                Log.d(logTag, perm.name);

                for (String suspPerm : suspiciousPermissions) {
                    if (suspPerm.equals(perm.name)) count++;
                }
            }
        }

        if (count > 3) {
            Log.d(logTag, "Suspected application identified by potentially offensive permissions - " + packageInfo.packageName);
            return true;
        }

        return false;
    }

    /**
     * Method returns set of AccessibilityServices package names currently
     * enabled in a device's settings and listed in the configurable appDetectionConfigs.
     * @return Set<String> This returns set of package name strings.
     */
    public Set<String> getSuspiciousAccessibilityServicesEnabled() {
        Set<String> retApps = new HashSet<>();
        Set<String> serviceIDsIEnabled = getAccessibilityServiceIDsEnabled();

        for (AppDetectionConfig appConfig : appDetectionConfigs) {
            for (String packageName : appConfig.appPackageNames) {
                if (serviceIDsIEnabled.contains(packageName)) {
                    Log.d(logTag, "Suspicious AccessibilityService Enabled - " + packageName);
                    retApps.add(packageName);
                }
            }
        }

        for (String packageName : serviceIDsIEnabled)
            if (isInstalledByKnownDangerousApp(packageName)) {
                Log.d(logTag, "AccessibilityService installed by a suspicious application - " + packageName);
                retApps.add(packageName);
            }

        return retApps;
    }

    /**
     * Method returns set of AccessibilityServices package names currently
     * installed on a device and listed in the configurable appDetectionConfigs.
     * @return Set<String> This returns set of package name strings.
     */
    public Set<String> getSuspiciousAccessibilityServicesInstalled() {
        Set<String> retApps = new HashSet<>();
        List<String> serviceIDsInstalled = getAccessibilityServiceIDsInstalled();

        for (AppDetectionConfig appConfig : appDetectionConfigs) {
            for (String packageName : appConfig.appPackageNames) {
                if (serviceIDsInstalled.contains(packageName)) {
                    Log.d(logTag, "Suspicious AccessibilityService installation detected - " + packageName);
                    retApps.add(packageName);
                }
            }
        }

        for (String packageName : serviceIDsInstalled)
            if (isInstalledByKnownDangerousApp(packageName)) {
                Log.d(logTag, "AccessibilityService installed by a suspicious application - " + packageName);
                retApps.add(packageName);
            }

        return retApps;
    }

    /**
     * Method returns set of AccessibilityServices package names currently
     * installed on a device.
     * @return Set<String> This returns set of package name strings.
     */
    public List<String> getAccessibilityServiceIDsInstalled() {
        List<AccessibilityServiceInfo> services = getAccessibilityServicesInstalled();
        List<String> serviceIDs = new ArrayList<>();
        for (AccessibilityServiceInfo svc : services)
            serviceIDs.add(svc.getId().split("/")[0]);

        return serviceIDs;
    }

    /**
     * Method returns list of AccessibilityServiceInfo currently
     * installed on a device; excludes system apps.
     * @return List<AccessibilityServiceInfo> This returns list of AccessibilityServiceInfo.
     */
    public List<AccessibilityServiceInfo> getAccessibilityServicesInstalled() {
        AccessibilityManager am = (AccessibilityManager) mContext.getSystemService(Context.ACCESSIBILITY_SERVICE);
        List<AccessibilityServiceInfo> services = am.getInstalledAccessibilityServiceList();

        List<AccessibilityServiceInfo> retSvcs = new ArrayList<>();
        PackageManager pm = mContext.getPackageManager();
        for (AccessibilityServiceInfo svc : services) {
            PackageInfo packageInfo = null;
            try {
                packageInfo = pm.getPackageInfo(svc.getId().split("/")[0], 0);
            } catch (PackageManager.NameNotFoundException e) {
                // pass Exception, packageName not found
            }

            if (packageInfo == null)
                continue;

            if ((packageInfo.applicationInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0)
                retSvcs.add(svc);
        }

        return retSvcs;
    }

    /**
     * Method returns set of AccessibilityService package names currently
     * enabled in a device's settings.
     * @return Set<String> This returns set of package name strings.
     */
    public Set<String> getAccessibilityServiceIDsEnabled() {
        List<AccessibilityServiceInfo> services = getAccessibilityServicesEnabled();
        Set<String> serviceIDs = new HashSet<>();
        for (AccessibilityServiceInfo svc : services)
            serviceIDs.add(svc.getId().split("/")[0]);

        return serviceIDs;
    }

    /**
     * Method returns list of AccessibilityServiceInfo currently
     * enabled in a device's settings; excludes system apps.
     * @return List<AccessibilityServiceInfo> This returns list of AccessibilityServiceInfo.
     */
    public List<AccessibilityServiceInfo> getAccessibilityServicesEnabled() {
        AccessibilityManager am = (AccessibilityManager) mContext.getSystemService(Context.ACCESSIBILITY_SERVICE);
        List<AccessibilityServiceInfo> services = am.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_GENERIC |
                        AccessibilityServiceInfo.FEEDBACK_VISUAL |
                        AccessibilityServiceInfo.FEEDBACK_HAPTIC);

        List<AccessibilityServiceInfo> retSvcs = new ArrayList<>();
        PackageManager pm = mContext.getPackageManager();
        for (AccessibilityServiceInfo svc : services) {
            PackageInfo packageInfo = null;
            try {
                packageInfo = pm.getPackageInfo(svc.getId().split("/")[0], 0);
            } catch (PackageManager.NameNotFoundException e) {
                // pass Exception, packageName not found
            }

            if (packageInfo == null)
                continue;

            if ((packageInfo.applicationInfo.flags &  (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0)
                retSvcs.add(svc);
        }
        
        return retSvcs;
    }

    /**
     * Method returns list of all installed AccessibilityService package
     * names that uses suspicious capabilities.
     * @return Set<String> This returns list of package name strings.
     */
    public Set<String> getAccessibilityServicesWithSuspiciousSettingsInstalled() {
        Set<String> retApps = new HashSet<>();

        List<AccessibilityServiceInfo> servicesInstalled = getAccessibilityServicesInstalled();
        for (AccessibilityServiceInfo svc : servicesInstalled) {
            int failCount = 0;

            // checks for remote controllers such as TeamViewer/AnyDesk
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                if ((svc.getCapabilities() & CAPABILITY_CAN_PERFORM_GESTURES) != 0)
                    failCount += 3;
            }

            if (svc.feedbackType == AccessibilityServiceInfo.FEEDBACK_GENERIC)
                failCount += 1;
            if (svc.eventTypes == 0)
                failCount += 2;
            if (svc.getSettingsActivityName() == null)
                failCount += 1;
            if (svc.notificationTimeout == 0)
                failCount += 1;
            if (svc.packageNames == null)
                failCount += 2;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                PackageManager pm = mContext.getPackageManager();
                if (svc.loadSummary(pm) == null)
                    failCount += 1;
            }

            if (failCount > 6) {
                String pkgSvcName = svc.getId().split("/")[0];
                Log.d(logTag, "Suspicious AccessibilityService installation detected based on remote control checks - " + pkgSvcName);
                retApps.add(pkgSvcName);
            }

            // checks for keyloggers such as Anubis
            failCount = 0;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                if ((svc.getCapabilities() & CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT) != 0)
                    failCount += 1;
            }
            if (svc.packageNames == null)
                failCount += 1;
            if ((svc.eventTypes & (TYPE_WINDOW_STATE_CHANGED | TYPE_WINDOW_CONTENT_CHANGED | TYPE_VIEW_FOCUSED)) != 0)
                failCount += 3;
            if (svc.feedbackType == AccessibilityServiceInfo.FEEDBACK_GENERIC || svc.feedbackType == 0)
                failCount += 1;
            if ((svc.flags & FLAG_REPORT_VIEW_IDS) != 0)
                failCount += 2;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                PackageManager pm = mContext.getPackageManager();
                if (svc.loadSummary(pm) == null)
                    failCount += 1;
            }

            if (failCount > 5) {
                String pkgSvcName = svc.getId().split("/")[0];
                Log.d(logTag, "Suspicious AccessibilityService installation detected based on keylogger checks - " + pkgSvcName);
                retApps.add(pkgSvcName);
            }
        }

        return retApps;
    }

    /**
     * Method returns list of AccessibilityService package
     * names that were installed in a similar time to applications
     * with suspicious permissions. In Android 11 and higher it may require
     * QUERY_ALL_PACKAGES permission.
     * @return Set<String> This returns list of package name strings.
     */
    public Set<String> getAppsWithCorrelatedInstallTimesWithSuspiciousApps() {
        List<String> accessibilityServiceIDsInstalled = getAccessibilityServiceIDsInstalled();
        PackageManager pm = mContext.getPackageManager();
        Set<String> retApps = new HashSet<>();
        List<PackageInfo> installedPackages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES);

        for (String svcPackageName : accessibilityServiceIDsInstalled)
            for (PackageInfo installedPackageInfo : installedPackages) {
                PackageInfo svcInstalledPackageInfo;

                try {
                    svcInstalledPackageInfo = pm.getPackageInfo(svcPackageName, PackageManager.GET_PERMISSIONS);
                } catch (PackageManager.NameNotFoundException e) {
                    // pass Exception, packageName not found
                    continue;
                }

                if ((svcInstalledPackageInfo.applicationInfo.flags & installedPackageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0)
                    continue;
                if ((svcInstalledPackageInfo.applicationInfo.flags & installedPackageInfo.applicationInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0)
                    continue;
                if (svcPackageName.equals(installedPackageInfo.packageName))
                    continue;
                if (Math.abs(svcInstalledPackageInfo.firstInstallTime - installedPackageInfo.firstInstallTime) > 15 * 60 * 1000)
                    continue;

                int count = 0;
                if (installedPackageInfo.requestedPermissions != null) {
                    for (String perm : installedPackageInfo.requestedPermissions){
                        for (String suspPerm : suspiciousPermissions) {
                            if (perm.equals(suspPerm)) count++;
                        }
                    }
                }

                if (installedPackageInfo.permissions != null) {
                    for (PermissionInfo perm : installedPackageInfo.permissions) {
                        for (String suspPerm : suspiciousPermissions) {
                            if (suspPerm.equals(perm.name)) count++;
                        }
                    }
                }

                if (count > 3) {
                    Log.d(logTag, "Suspected application identified by installation time correlation - " + svcPackageName);
                    retApps.add(svcPackageName);
                }
            }

        return retApps;
    }

    /**
     * Method returns list of AccessibilityService package
     * names that were installed in last 15 minutes.
     * @return Set<String> This returns list of package name strings.
     */
    public Set<String> getAvailabilityServicesInstalledInLastQuarter() {
        Set<String> retApps = new HashSet<>();
        PackageManager pm = mContext.getPackageManager();
        List<String> accessibilityServiceIDsInstalled = getAccessibilityServiceIDsInstalled();

        for (String svcPackageName : accessibilityServiceIDsInstalled) {
            PackageInfo svcInstalledPackageInfo;

            try {
                svcInstalledPackageInfo = pm.getPackageInfo(svcPackageName, PackageManager.GET_PERMISSIONS);
            } catch (PackageManager.NameNotFoundException e) {
                // pass Exception, packageName not found
                continue;
            }

            if (Math.abs(svcInstalledPackageInfo.firstInstallTime - System.currentTimeMillis()) > 15 * 60 * 1000)
                continue;

            retApps.add(svcPackageName);
        }

        return  retApps;
    }

    public Set<String> getAccessibilityServicesPermittedToOverlay(){
        Set<String> retApps = new HashSet<>();
        List<String> accessibilityServiceIDsInstalled = getAccessibilityServiceIDsInstalled();
        PackageManager pm = mContext.getPackageManager();

        for (String svcPackageName : accessibilityServiceIDsInstalled) {
            PackageInfo svcInstalledPackageInfo = null;

            try {
                svcInstalledPackageInfo = pm.getPackageInfo(svcPackageName, PackageManager.GET_PERMISSIONS);
            } catch (PackageManager.NameNotFoundException e) {
                // pass Exception, packageName not found
            }

            if ((svcInstalledPackageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0)
                continue;
            if (svcInstalledPackageInfo == null)
                continue;

            if (svcInstalledPackageInfo.permissions != null)
                for (PermissionInfo perm : svcInstalledPackageInfo.permissions) {
                    if (perm.name.equals("android.permission.SYSTEM_ALERT_WINDOW")) {
                        Log.d("allowed", svcInstalledPackageInfo.packageName);
                        retApps.add(svcInstalledPackageInfo.packageName);
                    }
                }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && svcInstalledPackageInfo.requestedPermissions != null)
                for (String permName : svcInstalledPackageInfo.requestedPermissions) {
                    if (permName.equals("android.permission.SYSTEM_ALERT_WINDOW")) {
                        Log.d("allowed", svcInstalledPackageInfo.packageName);
                        retApps.add(svcInstalledPackageInfo.packageName);
                    }
                }
        }

        return retApps;
    }

    /**
     * Method returns list of package names that are associated
     * with currently used ports. It is configurable by appDetectionConfigs.
     * In a PoC versions it uses netstat binary which is pretty common in Android environment.
     * Won't work in Android 10 and higher due to selinux hardening.
     * In case of Android 10 and above using port scanning techniques is recommended.
     * @return Set<String> This returns list of package name strings.
     */
    public Set<String> getAppsWithSuspiciousPortsInUse() {
        HashSet<String> retApps = new HashSet<>();

        String result = "";
        try {
            // Executes the command.
            String[] cmdline = {"netstat", "-tulpn"};
            Process pr = Runtime.getRuntime().exec(cmdline);
            BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(pr.getErrorStream()));
            String line;

            while ((line = input.readLine()) != null) {
                result += line;
                result += "\n";
            }
            while ((line = stdError.readLine()) != null) {
                result += line;
                result += "\n";
            }
            pr.waitFor();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        for (AppDetectionConfig appConfig : appDetectionConfigs) {
            List<String> ports = new ArrayList<>(appConfig.usedLocalPorts);
            ports.addAll(appConfig.usedRemotePorts);

            for (String port : ports) {
                String protocol = "tcp";
                if (port.startsWith("udp"))
                    protocol = "udp";
                String number = port.substring(3);
                Pattern pattern = Pattern.compile(protocol + ".*:" + number, Pattern.MULTILINE);
                Matcher matcher = pattern.matcher(result);

                if (matcher.find()) {
                    Log.d(logTag, "Suspicious port in use: " + port + " - " + appConfig.appName);
                    retApps.addAll(appConfig.appPackageNames);
                }
            }
        }

        return retApps;
    }

    /**
     * Method loads appDetectionConfigs.
     */
    void loadConfig(InputStream configFileStream) {
        Reader reader = new InputStreamReader(configFileStream);
        Gson gson = new Gson();
        appDetectionConfigs = gson.fromJson(reader, AppDetectionConfig[].class);
    }
}