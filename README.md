# Motivation

**Project aims to:**
* identify keyloggers and events hijacking malicious applications
* identify a "fake bank consultant scenario" when victim is requested to install remote control application and then log in to bank account


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

# Details
TBD

# Documentation
Code contains document comments, especially in RemoteDetector class. 

# Credits
TBD
