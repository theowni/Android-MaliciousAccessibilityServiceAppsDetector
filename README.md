***This project is not actively maintained** and may not work properly with the newest Android APIs. It serves as an idea for developing security checks against malicious AccessibilityServices*.

*Feel free to fork this repository and adjust to your needs. More context about this project is covered in https://devsec-blog.com/2024/03/detecting-banker-malware-installed-on-android-devices/.*

---

# Motivation

**Project aims to help in:**
* identifying keyloggers and events hijacking malicious applications such as Anubis/TeaBot,
* identifying a "fake bank consultant scenario" when a victim is requested to install a remote control application and then log in to a bank account,
* identifying other suspicious applications abusing Android AccessibilityService mechanisms

The methods implemented in RemoteDetector class should not be considered as a comprehensive list of checks. It's a PoC that provides you a way to collect more pieces of information about potentially suspicious applications and implement propper checks. However, some of the presented checks may be highly effective in your environments.

**Furthermore, you may want to implement your custom checks to outpace bad actors.**

# Demos

## Anubis Detection

https://user-images.githubusercontent.com/10147168/118893109-35e1dd80-b902-11eb-87e9-4c7695a99836.mp4

## Remote Control App Detection

https://user-images.githubusercontent.com/10147168/118893245-67f33f80-b902-11eb-8174-4a53a61329f8.mp4

# Description
The project aims to provide a way to detect when an Android device might be controlled or some events hijacked/keylogged. The application is a PoC that helps in identifying modern bankers such as Anubis/TeaBot, potentially malicious and remote controlling applications abusing Android AccessibilityService.

Modern banker apps abuse [AccessibilityService](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService) that was created to assist users with disabilities in using Android devices and apps. They run in the background and receive callbacks by the system when AccessibilityEvents are fired. Such events denote some state transition in the user interface, for example, the focus has changed, a button has been clicked, etc. 

RemoteDetector Java class allows to:
* list suspicious applications _(configurable by a list of packages)_
* list installed applications with suspicious AccessibilityService capabilities
* list applications with enabled AccessibilityService which uses suspicious capabilities
* list applications that uses suspicious ports _(PoC currently works for Android < 10)_
* list suspicious applications installed in last 15minutes 
* list suspicious applications that installTime is similar to AccessibilityService package installTime _(if different packages)_

# Usage

Example usage can be found in MainActivity class.
Specifically, the following code performs checks if a suspicious application was installed in last 15minutes and is currently enabled as AccessibilityService:

```java
Set<String> appsWithSuspiciousASvcsEnabled = remoteDetector.getSuspiciousAccessibilityServicesEnabled();
Set<String> appsInstalledInLastQuarter = remoteDetector.getAvailabilityServicesInstalledInLastQuarter();
Set<String> appsWithCorrelatedInstallTimesWithSuspiciousApps = remoteDetector.getAppsWithCorrelatedInstallTimesWithSuspiciousApps();

if (Sets.intersection(
                Sets.intersection(appsWithSuspiciousASvcsEnabled, appsInstalledInLastQuarter),
                appsWithCorrelatedInstallTimesWithSuspiciousApps).size() > 0) {
            Log.d(logTag, "Recently installed and enabled suspicious AccessibilityService!");
        }
```


Another example that may aid with detection malicious application that can draw over other apps:

```java
Set<String> accessibilityServicesPermittedToOverlay = remoteDetector.getAccessibilityServicesPermittedToOverlay();
Set<String> appsWithSuspiciousASvcsSettings = remoteDetector.getAccessibilityServicesWithSuspiciousSettingsInstalled();

if (Sets.intersection(
                Sets.intersection(remoteDetector.getAccessibilityServiceIDsEnabled(), appsWithSuspiciousASvcsSettings),
                accessibilityServicesPermittedToOverlay)
                .size() > 0) {
            Log.d(logTag, "Suspicious AccessibilityService enabled and can draw over apps");
            ((Switch) findViewById(R.id.switch31)).setChecked(true);
        }
```

List of detectable remote control application can be configured via `/res/raw/appconfigs.json` file 

More methods can be found in "RemoteDetector" class.

# Details

The RemoteDetector uses information provided by Android API, especially by [AccessiblityManager](https://developer.android.com/reference/android/view/accessibility/AccessibilityManager) and [PackageManager](https://developer.android.com/reference/android/content/pm/PackageManager).

AccessibilityServices currently enabled on a device can be listed via [getEnabledAccessibilityServiceList](https://developer.android.com/reference/android/view/accessibility/AccessibilityManager#getEnabledAccessibilityServiceList(int)).

To obtain capabilities used by AccessibilityServices [getCapabilities](https://developer.android.com/reference/android/accessibilityservice/AccessibilityServiceInfo#getCapabilities()) method is used. For example, to verify if a service can perform gestures, the following code returns true:

```java
if ((svc.getCapabilities() & CAPABILITY_CAN_PERFORM_GESTURES) != 0)
    return true;
```

Specific pieces of information about suspicious applications are obtained from PackageManager class.

To draw over application the [SYSTEM_ALERT_WINDOW](https://developer.android.com/reference/android/Manifest.permission#SYSTEM_ALERT_WINDOW) is commonly utilised by malicious applications.

# Documentation
Code contains document comments, especially in RemoteDetector class. 

# Credits to
All Android malware analytics publishing their researches, especially for:
* https://labs.f-secure.com/blog/how-are-we-doing-with-androids-overlay-attacks-in-2020/
* https://www.cleafy.com/documents/teabot
