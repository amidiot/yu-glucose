# Sibionics / SISENSING GS3 CGM — BLE 프로토콜 분석

작성일: 2026-09-11
조사 대상: Juggluco 소스 (커밋 `23ebeaa`, 2026-09-02, v11.0.1), gluco-glance, xDrip+, DiaBLE, Juggluco GitHub issues/discussions, juggluco.nl 문서
대상 장치: `GS3*-BEANLA` / `SISENSING-GNL` / 광고명 `AAC25A47AA44`

> **표기 규칙**
> - **[확인됨]** : 실제 소스 코드에서 직접 읽어 확인한 내용 (파일:줄 명시)
> - **[검증됨]** : 소스의 상수를 실제로 계산해서 교차 검증한 내용
> - **[추정]** : 코드/문서에서 직접 나오지 않고 정황으로 추정한 내용 (근거 명시)
> - **[미확인]** : 캡처 없이는 알 수 없는 내용

동봉된 `tools/gs3_protocol.py` 는 아래 내용을 그대로 옮긴 파이썬 참조 구현이다. `python3 tools/gs3_protocol.py selftest` 로 RC4 키 검증과 패킷 빌더/파서 셀프테스트가 돌아간다. **실제 GS3 하드웨어와는 아직 검증되지 않았다.**

---

## 0. 한 줄 요약

GS3 는 FF30/FF31/FF32 위에서 **고정 16바이트 키의 RC4** 로 모든 프레임을 XOR 하는 "암호화"를 쓴다. 키 교환도 없고 IV/nonce 도 없으며 패킷마다 같은 키스트림을 새로 시작한다. 인증은 `[BLE MAC 6바이트 + 앱 고정 키 16바이트]` 를 보내는 것이고, 그 뒤에 **계정 ID(64bit 정수) 바인딩** 이 온다. 이 계정 ID 만 맞으면 공식 앱이 활성화한 센서도 그대로 이어받을 수 있고, 인터넷 없이 로컬 BLE 만으로 5분 간격 혈당을 계속 받을 수 있다. Juggluco 는 이 전부를 Java + C++ 로 공개 구현했으며 난독화나 바이너리 블롭은 없다 (GS1 과 달리 벤더 알고리즘 .so 도 필요 없다).

---

## 1. 조사 방법과 범위

| 항목 | 내용 |
|---|---|
| Juggluco | `git clone --filter=blob:none` 전체 히스토리 426 커밋. 코드/커밋/README/도움말 리소스 전수 grep |
| gluco-glance | 전체 클론. GS1 평문 프로토콜 구현, GS3 미지원 이유 확인 |
| xDrip+ | shallow clone. Sibionics 직접 BLE 구현 없음 (공식 앱 알림 스크래핑용 패키지명만 존재) |
| DiaBLE (iOS) | shallow clone. Sibionics/GS3 관련 코드 없음 |
| GitHub issue/discussion | Juggluco #100, #181, #290, #405, xDrip #3063 — 프로토콜 세부는 전혀 공개되지 않음 |
| juggluco.nl | sensors 페이지, gs3number / SibionicsServer 도움말 |

검색 키워드(GS3, Sibionics, SISENSING, SISENSING-GNL, BEANLA, FF30/31/32, newSI, decrypt/encrypt/AES/auth/challenge) 는 위 4개 저장소 안에서 교차 검색했다. GitHub 전역 코드 검색은 이 세션의 API 범위 밖이어서 웹 검색으로 대체했으며, Juggluco 외에 GS3 프로토콜을 구현한 공개 프로젝트는 찾지 못했다. JugglucoNG(ctqvva) 는 UI 포크로, 프로토콜 코드는 Juggluco 것을 그대로 쓴다.

### 1.1 Juggluco 안의 GS3 구현 위치 [확인됨]

| 파일 | 역할 |
|---|---|
| `Common/src/mobileSi/java/tk/glucodata/Si3GattCallback.java` | GS3 전용 BLE GATT 콜백. 연결 → MTU → discover → FF31 notify → 인증 write → 이후 notify 마다 native 에 넘겨 다음 명령을 받아 write |
| `Common/src/main/cpp/sibionics3/interpretgs3.cpp` | GS3 명령 빌더, 수신 패킷 해석, handshake 상태 전이, 혈당 레코드 파싱 |
| `Common/src/main/cpp/sibionics3/java.cpp` | JNI 글루 (`gs3Glucose`, `gs3nfc`, `saveGS3id`, `getGS3id`, `md5sum`) |
| `Common/src/main/cpp/sibionics/interpret_data.cpp` | **RC4 키(`rc4key[16]`)** 와 `Rc4XorWithKey()`, 앱 키 테이블 `getkey()`, 인증 패킷 `v120_apply_authentication()` (GS1 newSI 와 GS3 가 공유) |
| `Common/src/main/cpp/sibionics/handleData.cpp` | `siAuthBytes()` JNI, 시간 동기 명령 `getSItimecmd()` |
| `Common/src/main/cpp/sibionics/makeWriteCharacter.cpp` | MAC 문자열 → 6바이트 역순 변환 `deviceArray()` |
| `Common/src/mobile/java/tk/glucodata/GS3ID.java` | Sibionics 서버 로그인 → 계정 ID 조회 (HTTP) |
| `Common/src/mobileSi/java/tk/glucodata/GetGS3ID.java` | 계정 ID 입력/조회 UI |
| `Common/src/mobileSi/java/tk/glucodata/Sib3Scan.java` | 센서 NFC(NDEF Text) 스캔 |
| `Common/src/main/cpp/sensoren.hpp:642` | `genMakeSI3sensorIndex()` 센서 등록 (`SibionGS3-` + BLE 이름 끝 6자) |
| `Common/src/main/cpp/settings/settings.hpp:427` | `uint8_t gs3id[12]` 계정 ID 저장 |

커밋 이력 [확인됨]: GS3 지원은 `63197a8` (2026-06-22, v10.9.3) 에서 Java 파일들이 추가됐고, C++ 쪽 `sibionics3/` 은 `bdaf792` (2026-07-03, 커밋 메시지 "missing") 에서 뒤늦게 공개됐다. `5297da7` (v10.9.6) 에서 NFC 파싱 보강, `43fdbe1` (v11.0.1) 에서 GATT 재연결 안정화. 즉 **현재 저장소에는 GS3 구현이 전부 공개되어 있다.**

벤더 함수명 (`v120_apply_authentication`, `V120SpiltData`, `v120RegisterKey`, `V120IsecUpdate`, `V120RawData`, `V120Activation`, `V120Reset`, `Java_com_no_sisense_enanddecryption_CGMDataHandle130_*`) 이 `sibionics/jnidef.h` 와 주석에 남아 있다. Juggluco 는 원래 공식 앱의 `libdata-handle-lib.so` 를 dlopen 했다가 (`sibionics/start.cpp` `getDatahandle()`, `JNI_HANDLE` 조건부) 지금은 Ghidra/Binary Ninja 로 디컴파일한 결과를 C++ 로 다시 써 넣었다 (주석: "RC4(key @ 0x2ffd9 [arm32] / 0x122e9e [arm64])", "BN names: var_228 ..."). → **핵심 구현은 native 소스에 평문으로 존재하며 바이너리 블롭에 숨어 있지 않다.** GS1 계열이 필요로 하는 벤더 알고리즘 라이브러리(`libnative-algorithm-*.so`) 는 GS3 경로에서 호출되지 않는다 (`interpretgs3.cpp` 는 `process2/3` 를 쓰지 않고 센서가 준 mmol/L 값을 그대로 사용).

---

## 2. 장치 식별 (스캔 / NFC / 데이터매트릭스)

### 2.1 광고 패킷

- Service UUID `FF30` 로 스캔 필터 [확인됨] `Si3GattCallback.getService()` (짝수 번째 시도는 필터 없이 스캔).
- 광고 이름 끝 6자 == 등록된 센서 이름 끝 6자 로 매칭 [확인됨] `Si3GattCallback.matchDeviceName()` (`SerialNumber` 는 `SibionGS3-18AAFZ` 형식, `sensoren.hpp:645`).
- Service Data `5347` = ASCII `"SG"`. 사용자의 값 `33 2A 2D 42 45 41 4E 4C 41` 는 ASCII **`3*-BEANLA`** 즉 모델명 `GS3*-BEANLA` 의 뒷부분 [검증됨]. Juggluco 는 UUID 상수만 정의하고 사용하지 않는다.
- Manufacturer Data `55AA 00B9 0000 0000 46F2 1059` : Juggluco 는 파싱하지 않음. 의미 [미확인].
- SMP 서비스 `8D53DC1D-…` / `DA2E7828-…` 는 Zephyr/MCUmgr SMP(DFU) 표준 UUID 이며 혈당 경로와 무관 [확인됨: 표준 UUID 일치, Juggluco 미사용].
- 표준 Glucose Service 0x1808 없음 — 예상대로.

### 2.2 NFC 태그 (NDEF Text record) [확인됨] `sibionics3/java.cpp gs3nfc()`, `Sib3Scan.java`

센서 자체가 NDEF Text 레코드를 가진 NFC-A 태그다. 예시(소스 주석):

```
GJ,GS3*-BEABMA,GNL,AAC25B18AAFZ,E2AFF9F01F19,PG291,HT
```

- 문자 3~5 가 `GS3` 이면 GS3 국제판 (`siType=4`), 아니면 `siType=5` (중국판).
- 콤마 4번째 필드(0-based 3) `AAC25B18AAFZ` = **BLE 광고 이름**, 끝 6자 `18AAFZ` 가 매칭 키.
- 5번째 필드 `E2AFF9F01F19` : Juggluco 는 사용하지 않지만 형식상 **BLE MAC(E2:AF:F9:F0:1F:19, random static)** 으로 보인다 [추정] — iOS 처럼 MAC 을 API 로 못 얻는 플랫폼에서 인증 패킷을 만들려면 이 필드가 핵심이므로 **캡처로 반드시 확인** 해야 한다 (§9).
- 6번째 `PG291`, 7번째 `HT` [미확인].

### 2.3 포장 데이터매트릭스 (GS1 바코드) [확인됨] `sensoren.hpp:880-925`

제조사 GS1 prefix `6972831`, SKU `64221` → GS3 국제판 (`siType=4`, 시리얼 끝 10자 중 끝 6자를 BLE 이름 매칭에 사용), SKU `64300` → 중국판 (`siType=5`, PIN 끝 6자 사용). `64016` 은 GS1, `64148` 은 트랜스미터.

### 2.4 siType 와 앱 키 선택 [확인됨] `interpret_data.cpp getkey()`

| siType | 공식 앱 패키지 | 16바이트 앱 키 |
|---|---|---|
| 0 | com.sisensing.sijoy (GS1) | `THE544U0TYITE461` |
| 1 | com.sisensing.rusibionics | `LQSS54U0RURUA99J` |
| 2 | com.sisensing.sisensingcgm | `GKSHGDU0TYA456G4` |
| 3 | com.sisensing.eco (GS1 CN) | `GKSHGDU0TYA456G4` |
| **4** | **com.sisensing.gs3 (GS3 국제)** | **`THE544U0TYITE461`** |
| 5 | com.sibionics.gstoc (GS3 CN, 주석 "Guess") | `GKSHGDU0TYA456G4` |

DIS Manufacturer 문자열이 `CN` 으로 끝나면 `Natives.isChinese()` 로 siType=5 로 바꾼다 (`Si3GattCallback.java:248`). 사용자의 장치는 `SISENSING-GNL` 이므로 **siType 4, 키 `THE544U0TYITE461`**.

---

## 3. 암호화 [확인됨 + 검증됨]

| 항목 | 값 |
|---|---|
| 알고리즘 | **RC4** (KSA + PRGA, drop 없음) — `interpret_data.cpp:312 Rc4XorWithKey()` |
| 키 | 고정 16바이트 `01 38 0B 9A 00 5B 02 5D CD 9E C3 99 09 37 AA E8` — `interpret_data.cpp:47 rc4key[16]` |
| 모드/IV/nonce | **없음.** 매 패킷마다 S-box 를 새로 초기화 → 모든 패킷이 동일한 키스트림 접두어와 XOR 됨 |
| 키 파생 | 없음. 시리얼/MAC/계정 ID 는 키에 관여하지 않음 |
| 방향 | 송신·수신 모두 같은 키, 같은 함수 (XOR 이므로 encrypt == decrypt) |
| 예외 | 평문 `04 00 00 00 FC` (cmd 0 의 ACK) 는 암호화 없이 올 수 있음 — `interpretgs3.cpp:396-412` |

키 검증 [검증됨]: GS1 코드가 실제 센서 트래픽과 비교하는 상수 두 개를 이 키로 복호화하면 정확한 프레임이 나온다.

```
RC4(23 F7 6F D9 F4) = 04 00 00 00 FC   (len 4, cmd 0, checksum FC = -4)   ← "인증 요구" ACK
RC4(24 E7 6F 34)    = 03 10 00 ED      (len 3, cmd 0x10, checksum ED)       ← GS1 reset 명령
keystream[0:16]     = 27 F7 6F D9 08 73 58 DC BD 81 86 03 0F B7 06 8C
```

따라서 **HCI 캡처만 있으면 `tools/gs3_protocol.py decrypt <hex>` 로 모든 패킷을 즉시 평문화할 수 있다.** (보안 관점: 키스트림 재사용 때문에 첫 바이트가 항상 `len`, 둘째가 `cmd` 인 것을 이용해 키 없이도 통계적으로 뚫리는 구조다.)

---

## 4. 프레임 구조 [확인됨]

모든 명령/응답의 평문은 같은 틀이다 (`interpret_data.cpp:75-100` 주석, `interpretgs3.cpp verify_checksum()`).

```
offset 0 : len      = 체크섬 바이트의 오프셋 (= 체크섬 앞 바이트 수)
offset 1 : cmd      (command id)
offset 2 : status / sub-command / seq / 레코드 수 (cmd 별로 다름)
offset 3…: payload
offset len : checksum = (-(sum of bytes[0..len-1])) & 0xFF   (프레임 전체 합 == 0 mod 256)
```

- **시퀀스 번호 필드는 없다.** 예외적으로 bindUser(0x13) 에 `seq` 바이트(1 → 재시도 2) 가 있다.
- 헤더 매직 없음. 길이 필드가 곧 프레이밍이며, 최대 250(0xFA) 바이트. Juggluco 는 MTU 247 을 요청한다.
- **ACK 프레임** 은 항상 5바이트 `04 <cmd> <result> <error> <cksum>`. `reply_ack_type = (cmd | 0xC000) + 1` 로 매핑 (벤더 enum).
- 정수는 모두 **little-endian** (GS1 구형 평문 프로토콜은 big-endian 이었으나 newSI/GS3 는 LE).

---

## 5. FF32 로 보내는 명령 (App → Sensor) [확인됨]

| cmd | 이름 (Juggluco/벤더) | 평문 형식 | 길이 | 소스 |
|---|---|---|---|---|
| 0x01 | 인증 `v120_apply_authentication` | `19 01 00 <MAC 6B 역순> <앱키 16B> <ck>` | 26 | interpret_data.cpp:424 |
| 0x13 | 계정 바인딩 `v120_glouse_id_bound` / `si3bendUser` | `0F 13 <seq> <gs3id 12B> <ck>` | 16 | interpretgs3.cpp:96 |
| 0xF0 | 장치 정보 요청 `v120_device_information` / `si3DeviceInfo` | `03 F0 <sub> <0x0D-sub>` (sub=1, 7 사용) | 4 | interpretgs3.cpp:74 |
| 0x0F | 활성화/시간 `v120_glouse_ketone_activation_nosens` / `si3NoSense` | `06 0F <u32 unix time> <ck>` | 7 | interpretgs3.cpp:186 |
| 0x03 | 시간 동기 `v120_isec_update` / `getSItimecmd` | `06 03 <u32 unix time> <ck>` | 7 | interpret_data.cpp:382, handleData.cpp:61 |
| 0x14 | 혈당 요청 `v120_gs3_raw_glouse_data` / `si3AskNewData` | `06 14 <u16 start> <u16 end=0> <ck>` | 7 | interpretgs3.cpp:51 |

- `gs3id[12]` = 계정 ID(int64) 를 **big-endian 8바이트** 로 넣고 나머지 4바이트는 0 (`java.cpp saveGS3id()` 의 `std::byteswap`). 계정 ID 예: `2019091906067780457`.
- MAC 역순: `deviceArray()` 가 `"E2:AF:F9:F0:1F:19"` → `19 1F F0 F9 AF E2`.
- 예시 벡터 (MAC E2:AF:F9:F0:1F:19, id 2019091906067780457, time 1700000000):

```
auth      plain 19 01 00 19 1F F0 F9 AF E2 54 48 45 35 34 34 55 30 54 59 49 54 45 34 36 31 07
          wire  3E F6 6F C0 17 83 A1 73 5F D5 CE 46 3A 83 32 D9 B2 E7 BD 05 76 C1 55 80 4F 0D
bindUser1 plain 0F 13 01 1C 05 41 64 16 09 53 69 00 00 00 00 3C   wire 28 E4 6E C5 0D 32 3C CA B4 D2 EF 03 0F B7 06 B0
devinfo 1 plain 03 F0 01 0C                                       wire 24 07 6E D5
devinfo 7 plain 03 F0 07 06                                       wire 24 07 68 DF
activate  plain 06 0F 00 F1 53 65 42                              wire 21 F8 6F 28 5B 16 1A
timesync  plain 06 03 00 F1 53 65 4E                              wire 21 F4 6F 28 5B 16 16
askData 1 plain 06 14 01 00 00 00 E5                              wire 21 E3 6E D9 08 73 BD
```

GS1 newSI 전용이라 GS3 경로에서 쓰이지 않는 명령: 0x08 raw data 요청(`06 08 idx16 start16`), 0x07 activation(`0A 07 time32 1234`), 0x10 reset(`03 10 00 ED`).

---

## 6. FF31 에서 받는 패킷 (Sensor → App) [확인됨] `interpretgs3.cpp gs3Glucose()`

| cmd | 형식 | Juggluco 처리 |
|---|---|---|
| (평문) `04 00 00 00 FC` | cmd 0 ACK, 미암호화 | 무시 (GS1 에서는 "인증하라" 신호) |
| 0x00–0x06, 0x0C, 0x0F–0x13 | 5바이트 ACK | `reply_ack_type` 별 상태 전이 (§7) |
| 0x14 (len 4) | ACK | 요청 접수 확인 → `result=3` |
| 0x14 (len > 4) | 혈당 레코드 묶음 (§8) | 파싱·저장 |
| 0x15 | `gs3_only_glouse_info` | 로그만 |
| 0x88 | `only_glouse_ketone_adc_info_t` | 로그만 |
| 0xF0 sub 1..13 | 장치 정보 응답 | sub 1 → devinfo 7 요청, sub 7 → 활성화/시간 전송, 나머지 로그만 |

0xF0 sub 목록(벤더 struct 이름): 1 u16 sensor reading, 2 u8 activation, 3 device time, 4 storage, 5 calibration(4×u32), **6 secret key(16B)**, 7 reset info(`iswatchdog,times,synchron,pad,index u16,pad u16,timestamp u32`), 8 glucose threshold, 9 oscillator, 10 watchdog, 11 glucose+ketone u16, 12 life, 13 device id(1+8B). Juggluco 는 6/13 등을 요청하지 않는다.

ACK 바이트 의미: `[2]=reply_ack_resule`, `[3]=error_code`. bindUser(0x13) ACK 에서 `error!=0 && resule==2` 이면 **"Wrong account ID"** (`interpretgs3.cpp:460`).

---

## 7. 연결 및 handshake 순서 [확인됨] `Si3GattCallback.java` + `interpretgs3.cpp handle_ack()`

```
[App]                                   [GS3 sensor]
 scan(filter FF30) / 이름 끝6자 매칭
 connectGatt (bond 없음, PIN 없음)
 requestMtu(247)  ──────────────────▶
 ◀────────────────────────────── onMtuChanged
 discoverServices ─────────────────▶
 (선택) DIS 0x2A29/0x2A24/… read (로그용)
 FF31 CCCD = 01 00 (notify 활성) ─────▶
 FF32 ◀ write  0x01 AUTH(MAC, 앱키)   ─▶            ← 첫 전송 (siAuthBytes)
 ◀── FF31  ACK(0x01)                                  (0xC002)
 FF32 ◀ write  0x13 BIND(seq=1, gs3id) ─▶
 ◀── FF31  ACK(0x13, resule, error)                   (0xC014)
        error==0            → 계속
        error!=0, resule==2 → "Wrong account ID", disconnect
        그 외 error         → BIND(seq=2) 재시도
 FF32 ◀ write  0xF0 DEVINFO(1) ─────────▶
 ◀── FF31  F0/01 (u16 sensor reading)
 FF32 ◀ write  0xF0 DEVINFO(7) ─────────▶
 ◀── FF31  F0/07 (reset info)
 FF32 ◀ write  0x0F ACTIVATION/TIME(now) ▶
 ◀── FF31  ACK(0x0F)                                  (0xC010)
 FF32 ◀ write  0x03 TIMESYNC(now) ───────▶
 ◀── FF31  ACK(0x03)                                  (0xC004)
 FF32 ◀ write  0x14 ASKDATA(start=last+1, end=0) ▶
 ◀── FF31  ACK(0x14)                                  (0xC015)
 ◀── FF31  0x14 records … (remaining>0 이면 과거, 0 이면 최신)
 ◀── FF31  0x14 records   (이후 분 단위 push)          [추정]
```

- 모든 전이는 "notify 1개 수신 → native 가 다음 명령 1개 반환 → write" 로 완전히 직렬적이다 (`deliverNotification()` → `gs3Glucose()` → `write2(uit.cmd)`).
- challenge-response 는 **없다.** 센서가 난수를 주지 않고 앱이 고정 값만 보낸다. "인증"은 `MAC + 앱키` 를 아는지 확인하는 수준.
- 0x14 데이터 수신 후 Juggluco 는 추가 요청을 보내지 않는다 (`case 0x14` 에서 `vect` 비어 있음). juggluco.nl: "센서는 매분 값을 보내지만 5분간 같은 값" → 연결 유지 중 센서가 분 단위로 push 한다고 본다 [추정]. 일정 시간 데이터가 없으면 `SuperGattCallback.shouldreconnect()` 가 재연결하고 handshake 를 처음부터 다시 한다 (start = 마지막 index+1 로 히스토리 복구).
- Write 타입: `writeCharacteristic()` 기본값(Write With Response). FF32 는 둘 다 지원하므로 어느 쪽이든 될 가능성이 높다 [추정].

---

## 8. 혈당 패킷 구조 및 변환 [확인됨] `interpretgs3.cpp:508-560`

```
[0]  len
[1]  0x14
[2]  count            레코드 수
[3]  u16 startIndex   첫 레코드의 index (센서 시작 후 분 단위 카운터)
[5]  u32 startTime    첫 레코드의 시각, unix epoch 초 (센서가 시간동기 명령으로 받은 시계 기준)
[9]  count × 8바이트 레코드
[len-2] u16 last_reindex   남은 레코드 수. 0 이면 이 묶음의 마지막 = 현재 값
[len] checksum
```

8바이트 레코드 (`r[0..7]`):

| 바이트 | 필드 |
|---|---|
| r0 | bit0 `twarn`, bit1 `shedding`, bit6-7 = temp 하위 2비트 |
| r1 | temp 상위 8비트 → `temp = (r1<<2) \| (r0>>6)` (10비트, 단위 미확인) |
| r2-3 | u16 `fieldB` (벤더 `dump`, 의미 미확인. 실기에서 하위 바이트 r2 가 서서히 드리프트) |
| r4-5 | u16 `fieldD` (벤더 `c1`. 과거 "원시 전류" 로 추정했으나 **실기에서 5시간+ 동안 `0x5aca=23242` 로 완전 고정** → 라이브 측정치가 아니라 고정 상수/미사용 필드로 정정) |
| r6 | bit0 `gcwarn`, **bit3-5 `trend`(0..4)**, bit6-7 = glucose 하위 2비트 |
| r7 | glucose 상위 8비트 → **`mmolLx10 = (r7<<2) \| (r6>>6)`** (10비트, 0.1 mmol/L 단위) |

변환: `mg/dL = round(mmolLx10 × 0.1 × 18.0)` (`convfactordL = 180.0 × 0.1`; 빌드 옵션에 따라 18.0182). 즉 **센서가 이미 보정된 mmol/L 값을 준다**. 원시 전류 → 혈당 알고리즘은 필요 없다 (GS1 과 결정적 차이).

- 시각: `eventTime = startTime + i×60`, 센서 시작 시각 `= eventTime − index×60` (`makestarttime()`). `index % 5 == 0` 인 레코드만 저장 (공식 앱의 5분 값과 일치).
- 트렌드: 0 flat, 1 slightly up(+1.05), 2 up(+4.0), 3 slightly down, 4 down (`sib3totrend()`). Juggluco 는 자체 회귀로 화살표를 다시 계산한다.
- 유효 범위 [추정, GS1 코드 준용]: 1.8 < mmol/L < 30.
- 웜업: Juggluco 는 `manualwarmup=45` 분 이후 값만 표시. 공식 웜업은 [미확인].
- 수명: `maxdaysSI3 = 24일`, 공식 종료 후 약 1.5일 더 준다 (juggluco.nl).

---

## 9. 질문별 답변 (Q1–Q17)

| # | 질문 | 답 | 근거 |
|---|---|---|---|
| 1 | 연결 절차 | §7. scan(FF30) → connect → MTU 247 → discover → FF31 notify → 인증 write → 직렬 handshake | **[확인됨]** Si3GattCallback.java:225-295 |
| 2 | FF30/31/32 사용 | 예. FF31 notify, FF32 write. DIS/Battery 는 로그용 read 만 | **[확인됨]** 동 파일 :74-99 |
| 3 | 최초 전송 데이터 | RC4(`19 01 00 <MAC 역순 6B> <THE544U0TYITE461> <ck>`) 26 B | **[확인됨]** handleData.cpp:86, interpret_data.cpp:424 |
| 4 | notify 이후 순서 | AUTH → BIND → DEVINFO1 → DEVINFO7 → ACT/TIME → TIMESYNC → ASKDATA | **[확인됨]** interpretgs3.cpp:446-486, 604-664 |
| 5 | challenge-response | 없음. 센서 난수 없음, 앱이 고정값 전송 | **[확인됨]** |
| 6 | 암호화 | RC4, 모드 없음, 고정 키, IV/nonce 없음, 시리얼/MAC/코드 무관 | **[확인됨+검증됨]** §3 |
| 7 | 패킷 구조 | `[len][cmd][payload][sum-to-zero ck]`, seq 없음(0x13 만 seq), LE | **[확인됨]** §4 |
| 8 | FF32 명령 | 0x01, 0x13, 0xF0(1/7), 0x0F, 0x03, 0x14 | **[확인됨]** §5 |
| 9 | FF31 패킷 | ACK(5B), 0x14 records, 0xF0 sub, 0x15, 0x88, 평문 hello | **[확인됨]** §6 |
| 10 | 혈당 패킷 | §8 | **[확인됨]** |
| 11 | 변환 | `(r7<<2\|r6>>6)` ×0.1 mmol/L, ×18 → mg/dL | **[확인됨]** |
| 12 | 시간 동기 | 앱이 0x0F, 0x03 으로 unix 초 전송; 응답의 startTime 은 unix 초; index 는 분 카운터 | **[확인됨]** |
| 13 | activation 필요 여부 | 별도 activation 명령 UI 없음. handshake 안의 0x0F(벤더명 activation) 이 새 센서에도 그대로 감. 새 센서는 임의 계정 ID 로 시작 가능 | **[확인됨]** juggluco.nl help + 코드; 0x0F 가 실제 "활성화" 인지는 **[추정]** |
| 14 | 공식 앱 센서 이어받기 | 가능. 같은 계정 ID(`user_id`) 만 있으면 됨. ID 는 서버 로그인 또는 루팅폰 `sp_user.xml` | **[확인됨]** GS3ID.java, html.xml:3250-3290 |
| 15 | pairing/bonding | 없음. createBond/PIN 호출 없음 | **[확인됨]** Si3GattCallback.java 전체 |
| 16 | 서버 key/token | 센서 통신용 키는 앱에 고정 내장. 서버에서 받는 것은 **계정 ID 숫자 하나** 뿐 (선택) | **[확인됨]** |
| 17 | 오프라인 지속 수신 | 가능. BLE 경로에 네트워크 호출 없음 | **[확인됨]** |

### 9.1 계정 ID 획득 API [확인됨] `GS3ID.java`

```
POST https://cgm.sibionics.io/center/app/user/login
  headers: lang=en_US, Content-Type=application/json, Sib-Agent="SIBIONICSGS3&01.08.00.00&android&android <rel>&<brand> <model>",
           timeZone=<tz>, User-Agent=okhttp/3.12.10, log-header="I am the log request header."
  body:    {"email":"<email>","loginType":0,"password":"<md5(password) hex>"}
  →  data.access_token, data.regionDomain (없으면 https://cgm-ce.sisensing.com)

GET  <regionDomain>/user/app/info   Authorization: <access_token>
  →  data.id  (문자열 정수, 예 "2019091906067780457")  = gs3id
```

루팅 폰이라면 `/data/data/com.sisensing.gs3/shared_prefs/sp_user.xml` 의 `user_id` 가 같은 값이다.

---

## 10. Pseudo code

```text
scan(serviceUUID = FF30)                       # 또는 이름 끝 6자 == NFC/데이터매트릭스 끝 6자
connect(device)                                # bonding 없음
requestMtu(247)
discoverServices()
subscribe(FF31)                                # CCCD 01 00

mac     = device.address                       # Android. iOS 는 NFC 5번째 필드(추정) 또는 캡처로 확인
appkey  = "THE544U0TYITE461"                   # siType 4 (SISENSING-GNL). CN 판은 "GKSHGDU0TYA456G4"
gs3id   = be64(account_id) + 00 00 00 00        # 12 B
rc4key  = 01 38 0B 9A 00 5B 02 5D CD 9E C3 99 09 37 AA E8

def frame(cmd, payload): body = [2+len(payload), cmd] + payload; return body + [(-sum(body)) & 0xFF]
def send(plain):          write(FF32, RC4(rc4key, plain))          # 패킷마다 새 키스트림
def recv():               return RC4(rc4key, notify(FF31))         # 단, 04 00 00 00 FC 는 평문

send(frame(0x01, [0x00] + reverse(mac) + appkey))                  # AUTH
loop:
    p = recv()
    if p[0] == 4:                                                    # ACK
        match p[1]:
            0x01: send(frame(0x13, [1] + gs3id))                     # BIND seq 1
            0x13: if p[3]==0: send(frame(0xF0,[1]))
                  elif p[2]==2: fail("Wrong account ID")
                  else: send(frame(0x13, [2] + gs3id))
            0x0F: send(frame(0x03, le32(now)))                       # TIME SYNC
            0x03: send(frame(0x14, le16(next_index) + le16(0)))      # ASK DATA
            0x14: pass                                               # 요청 접수
    elif p[1] == 0xF0:
        if p[2]==1: send(frame(0xF0,[7]))
        if p[2]==7: send(frame(0x0F, le32(now)))                     # ACTIVATION/TIME
    elif p[1] == 0x14 and checksum_ok(p):
        count, start_idx, start_time = p[2], le16(p[3:5]), le32(p[5:9])
        for i in range(count):
            r = p[9+8*i : 17+8*i]
            mmol_x10 = (r[7] << 2) | (r[6] >> 6)
            trend    = (r[6] >> 3) & 7
            idx      = start_idx + i
            t        = start_time + 60*i
            if idx % 5 == 0:
                glucose_mg_dl = round(mmol_x10 * 0.1 * 18.0)
                store(t, idx, glucose_mg_dl, trend)
        next_index = start_idx + count
```

실행 가능한 버전은 `tools/gs3_protocol.py` (`Gs3Session.on_notify()`).

---

## 11. 지금 확실히 구현 가능한 것 vs 캡처가 필요한 것

### 11.1 현재 정보만으로 구현 가능 [확인됨/검증됨]

- RC4 복호화/암호화 및 키 (실제 트래픽 상수로 교차 검증됨)
- 프레임 포맷·체크섬, 6개 명령 빌더, ACK/0x14/0xF0 파서
- handshake 상태 기계 전체 (Juggluco 가 실사용 중인 순서 그대로)
- 계정 ID 획득 (서버 API 또는 수동 입력), 새 센서는 임의 ID
- 혈당 값 추출과 mg/dL 변환, 타임스탬프, 히스토리 재요청 (start=last+1)
- Android 에서는 위만으로 끝까지 갈 수 있어야 한다. Juggluco 로 같은 센서가 실제로 붙는지 먼저 확인하면 (Juggluco 를 설치해 계정 ID 를 넣고 연결) 우리 구현의 기준선이 된다.

### 11.2 캡처(또는 실기 테스트)가 필요한 것

| 항목 | 이유 | 캡처 시나리오 |
|---|---|---|
| **iOS 에서 MAC 확보** | AUTH 에 MAC 이 들어감. iOS CoreBluetooth 는 MAC 을 안 줌 | Android nRF Connect 로 MAC 확인 ↔ NFC 5번째 필드 ↔ Manufacturer Data 비교 (한 번이면 됨) |
| 0x14 이후 push 여부/주기, `remaining` 동작 | 코드는 추가 요청을 안 보내는데 데이터가 어떻게 이어지는지 코드로는 확정 불가 | 공식 앱 또는 Juggluco 로 **연결 유지 10분+** 캡처 (실시간 update) |
| 최초 activation 정확한 시퀀스 | 0x0F 가 진짜 activation 인지, 공식 앱이 다른 명령(0xF0 sub 2 등)을 더 보내는지 | 공식 앱 **새 센서 활성화** 캡처 (가장 중요) |
| Write With/Without Response | 코드는 With Response, 센서가 둘 다 받는지 | 공식 앱 캡처의 ATT opcode 확인 |
| 히스토리 sync 의 `end` 파라미터, 한 패킷 최대 레코드 수, MTU 협상 값 | Juggluco 는 end=0 만 사용 | 공식 앱 **재연결(오래 끊었다 붙기)** 캡처 |
| ACK error/result 코드 표 | `sub_28ad0()` 테이블은 로그용, 의미 미상 | 실패 케이스(다른 계정 ID 로 시도) 캡처 |
| temp/current/dump 단위, warn 비트 의미 | 표시에 불필요하지만 알고 싶으면 | 공식 앱 화면값과 대조 |
| CN 판 앱 키 | Juggluco 도 "Guess" | CN 판 공식 앱 캡처 (해당 시) |
| 0xF0 sub 6 "secret key", sub 13 device id | 다른 인증 모드가 있는지 | 공식 앱 최초 연결 캡처에서 sub 6/13 요청 유무 확인 |

### 11.3 권장 캡처 방법

1. **Android HCI snoop log (btsnoop_hci.log) — 1순위.**
   개발자 옵션 → "Bluetooth HCI 스누프 로그 사용" → 공식 GS3 앱으로 (a) 새 센서 활성화, (b) 앱 강제종료 후 재연결, (c) 10분 이상 실시간, (d) 하루 뒤 재연결(히스토리) 를 각각 별도 로그로. `adb bugreport` 로 추출 → Wireshark 에서 `btatt.handle` / `btatt.uuid16 == 0xff31` 필터 → hex 를 `tools/gs3_protocol.py decrypt` 에 넣으면 평문과 해석이 바로 나온다. ATT 전체 (MTU 교환, CCCD write, opcode) 가 보여서 §11.2 항목 대부분이 한 번에 해결된다.
2. **iOS PacketLogger (Xcode → Bluetooth profile)**: iOS 공식 앱을 써야만 한다면 대안. HCI 수준이라 동일 정보. 단 MAC 은 여전히 iOS 가 random 하게 보일 수 있으니 MAC 확인은 Android 로.
3. **nRF Sniffer / Ellisys 같은 OTA 스니퍼**: 폰 없이도 되지만 연결 이벤트 추적이 번거롭고 얻는 정보는 HCI 로그와 같다. 필요 없음.
4. **Juggluco 로그 빌드** (`assembleMobileLibre3SiDexNogoogleReleaseLog`): `LOGGER("gs3Glucose decrypted …")`, `si3bendUser(…)=…` 로 평문/암호문이 다 찍힌다. Android 가 있으면 가장 빠른 교차검증.

---

## 11.4 실기 확인 결과 (2026-09-11, 사용자 센서)

iPhone 의 NFC Tools 앱과 포장 UDI 라벨에서 직접 읽은 값이다. **[실기 확인됨]**

| 항목 | 값 |
|---|---|
| NFC 태그 | ISO 14443-4 (Type 4 Tag, IsoDep), 제조 Shanghai Fudan Microelectronics, UID `1D:91:FD:23:87:00:00`, 60 B, 쓰기 가능 |
| NDEF Text | `GJ,GS3*-BEABMA,GNL,AAC25A47AA44,D2D921FC1B75,PG336,FL` |
| UDI (01) GTIN | `06972831641391` → 제조사 `6972831`, **SKU `64139`**, 검증 1 |
| UDI (21) SN | `25090447AA44AV35` (라벨 하단 `47AA44`) |
| UDI (10) LOT / (11) 생산 / (17) 만료 | `LT4E250904C` / 2025-10-31 / 2027-04-30 |
| BLE 광고 이름 (nRF Connect) | `AAC25A47AA44` |
| DIS Model / Manufacturer | `GS3*-BEANLA` / `SISENSING-GNL` |

해석:

- NDEF 4번째 필드 `AAC25A47AA44` 는 BLE 광고 이름과 **정확히 일치** → Juggluco 의 NFC 파싱(`gs3nfc()`: 오프셋 3 이 `GS3` → siType 4, 4번째 필드 = 장치명) 이 이 센서에 그대로 적용된다. 앱 키는 `THE544U0TYITE461`.
- NDEF 5번째 필드 `D2D921FC1B75` → **MAC 후보 `D2:D9:21:FC:1B:75`** [추정]. 첫 바이트 `D2` 의 상위 2비트가 `11` 이라 BLE random static 주소 형식과 맞고(Zephyr/nRF 기본), Juggluco 주석 예시 `E2AFF9F01F19` 와 같은 자리다. 확정은 Android nRF Connect·리눅스 등에서 실제 주소와 대조하거나, 이 값으로 AUTH 가 ACK 되는지 보면 된다.
- NFC 의 모델명은 `GS3*-BEABMA`, BLE DIS 는 `GS3*-BEANLA` 로 접미가 다르다. Juggluco 소스 주석의 예시도 NFC 쪽이 `BEABMA`, 광고명 형식이 `AAC25B18AAFZ` 로 같은 계열이므로, **Juggluco 저자가 개발에 쓴 것과 같은 국제판(GNL) 변종**으로 본다. "CN 판" 은 유통 경로 문제일 가능성이 높다.
- **SKU `64139` 는 Juggluco 의 포장 데이터매트릭스 분기 목록(`64221` GS3 국제, `64300` GS3 CN, `64016` GS1, `64148` 트랜스미터) 에 없다** (`sensoren.hpp:893-925`). GTIN 에 `0697283164` 가 포함돼 `hasnum` 이 참이 되므로 데이터매트릭스로 등록하면 `makeSIsensorIndex(…, 45)` 로 빠져 **GS1 으로 잘못 등록**된다. Juggluco 를 쓸 때는 반드시 **센서 NFC 로 등록**해야 한다 (NFC 경로는 SKU 를 보지 않는다). Juggluco 에 SKU 64139 추가를 제보할 만하다.
- SN `25090447AA44AV35` 의 7–12번째 문자 `47AA44` 가 광고명 끝 6자와 같다. Juggluco 의 `makeSI3sensorIndex()` 가 `Serial.end()-10` 에서 6자를 취하는 것과 일치한다.
- 센서는 공식 앱으로 활성화된 적이 없으므로 미바인딩 상태다. 계정 ID 는 임의 숫자를 정해 **첫 바인딩 값을 기록**해 두고 이후 모든 앱에서 같은 값을 쓴다.

이 센서용 패킷 (계정 ID 는 예시값 `2025090447004401`, time `1757606400`):

```
python3 tools/gs3_protocol.py vectors --mac D2:D9:21:FC:1B:75 --account-id 2025090447004401 --time 1757606400
auth      plain 19 01 00 75 1B FC 21 D9 D2 54 48 45 35 34 34 55 30 54 59 49 54 45 34 36 31 61
          wire  3E F6 6F AC 13 8F 79 05 6F D5 CE 46 3A 83 32 D9 B2 E7 BD 05 76 C1 55 80 4F 6B
bindUser1 plain 0F 13 01 00 07 31 CF 1C BB 52 F1 00 00 00 00 BC   wire 28 E4 6E D9 0F 42 97 C0 06 D3 77 03 0F B7 06 30
```

iOS 에서 남은 미확인 항목은 이제 "5번째 필드가 정말 MAC 인가" 와 "센서가 MAC 을 검증하는가" 둘뿐이며, 둘 다 위 AUTH 를 한 번 보내 보면 답이 나온다 (미바인딩 센서라 실패해도 잃을 것이 없다).

## 11.5 iPhone 에서 바로 보기: Web Bluetooth 페이지

`docs/gs3/index.html` 은 외부 의존성 없는 한 파일짜리 웹 뷰어다. RC4·프레이밍·handshake 상태 기계를 JS 로 옮겼고, 빌더 출력은 `tools/gs3_protocol.py` 의 벡터와 바이트 단위로 일치한다 (Node 로 검증).

- iOS Safari 는 Web Bluetooth 가 없다. App Store 의 **Bluefy – Web BLE Browser** (또는 WebBLE) 로 HTTPS 주소를 열어야 한다. Android/PC 는 Chrome 에서 바로 된다.
- 호스팅: 저장소를 public 으로 바꾼 뒤 Settings → Pages → Deploy from a branch → 브랜치 선택, 폴더 `/docs` → `https://amidiot.github.io/yu-glucose/gs3/`.
- 입력: MAC(NFC 5번째 필드), 계정 ID(미바인딩 센서면 임의 숫자, 첫 값을 영구 사용), 앱 키 변종. 값·기록은 localStorage 에 남고, 재접속 시 마지막 index+1 부터 요청한다.
- 한계: 페이지가 열려 있는 동안만 수신(백그라운드 없음). MTU 는 브라우저가 정하므로 긴 0x14 패킷이 잘리면 로그에 "MTU 로 잘렸을 가능성" 으로 표시된다. 모든 송수신 패킷을 wire/plain hex 로 로그에 남기므로 첫 연결 시도 자체가 §11.2 의 MAC 검증 실험이 된다.

## 11.6 실기 연결 성공 (2026-09-11, 사용자 센서, Bluefy/iOS 18.7) — 프로토콜 전 과정 검증됨

`docs/gs3/index.html` (Web Bluetooth) 로 실제 센서에 연결해 **handshake 전 과정과 혈당 레코드 수신까지 성공**했다. 이로써 문서의 [추정] 항목 다수가 [실기 확인됨] 으로 승격됐다.

**첫 연결 (미바인딩 → 바인딩):**

```
→ auth  (MAC D2:D9:21:FC:1B:75, key THE544U0TYITE461)
←        04 01 01 00     ACK 0xC002        ← MAC 정답. "NFC 5번째 필드 = MAC" 확정
→ bindUser seq1
←        04 13 01 04     error 4           ← 미바인딩, seq2 필요
→ bindUser seq2
←        04 13 02 00     성공              ← 계정 ID 로 바인딩 완료(영구)
→ deviceInfo1 → 05 f0 01 71 05  (value 0x0571=1393)
→ deviceInfo7 → 0c f0 07 00×9   (reset info 전부 0 = 측정기록 없음)
→ activation → 04 0f 01 00      ACK 0xC010
→ timeSync   → 04 03 01 00      ACK 0xC004
→ askNewData start=1 → 04 14 00 05   result0/error5 = 아직 데이터 없음
```

**~2분 뒤 재연결 (이미 바인딩됨):**

```
→ auth       → 04 01 01 00
→ bindUser seq1 → 04 13 01 00   error 0 → 한 번에 성공          ← 바인딩이 센서에 영구 저장됨을 입증
→ deviceInfo1/7, activation(04 0f 00 04), timeSync(04 03 01 00)
→ askNewData start=1 → 04 14 01 00   result1/error0 = 데이터 있음
←  1b 14 02 01 00 <startTime u32> <rec0 8B> <rec1 8B> 00 00 <ck>   ← glucose count=2, idx 1·2
   그리고 이후 idx=3 이 요청 없이 자발적으로 push (분당 1건)
```

**확정된 사실:**

- **MAC = NFC NDEF 5번째 필드** (D2:D9:21:FC:1B:75). 센서는 MAC 을 인증에 실제로 사용·검증한다.
- **바인딩은 영구.** 첫 연결은 seq1(error4)→seq2 로 신규 바인딩, 재연결은 seq1 즉시 성공. bindUser seq2 = "신규 바인딩 쓰기", seq1 = "기존 바인딩 확인".
- **askNewData ACK 의 result/error 가 데이터 유무를 알린다**: `result0/error5` = 없음(웜업), `result1/error0` = 뒤이어 레코드 push.
- **연결 유지 중 센서가 분당 1건씩 0x14 레코드를 자발적으로 push** (idx 3 이 요청 없이 수신됨). §7 의 [추정] 확정.
- **혈당 레코드 파싱 정확.** 웜업 중이라 `mmolLx10=0` 이지만 `temp=(r1<<2)|(r0>>6)`, `current=r4|r5<<8` 는 정상값(temp 317→319, current 23242). `tools/gs3_protocol.py` 와 웹 파서가 실제 캡처를 동일하게 디코드.
- **웜업**: 새 센서 첫 활성화 직후 temp/current 만 나오고 glucose=0. GS3 웜업 ~1시간 후 실제 mmol/L 이 나오기 시작할 것으로 예상 [추정].

남은 유일한 미확인은 "웜업 종료 후 실제 mmol/L 값의 정확도(공식 앱과 비교)" 뿐이며, 프로토콜·연결·복호화·파싱은 전부 검증됐다.

## 11.7 혈당 파싱 검증 (2026-09-11, "혈당이 아예 안 변한다" 보고에 대한 대조)

**Juggluco 원본과 바이트 단위 대조 [검증됨].** Juggluco `primary` 브랜치 커밋 `23ebeaa` (v11.0.1, 2026-09-02) 를 다시 받아 `Common/src/main/cpp/sibionics3/interpretgs3.cpp:508-539` 의 `case 0x14` 와 `tools/gs3_protocol.py` / `docs/gs3/index.html` 의 파서를 한 줄씩 대조했다.

| 항목 | Juggluco (`interpretgs3.cpp`) | 이 저장소 (py / html) | 일치 |
|---|---|---|---|
| count | `plain[2]` | `p[2]` | ✓ |
| startIndex | `*(uint16_t*)&plain[3]` (LE) | `struct <H @3` / `p[3]\|p[4]<<8` | ✓ |
| startTime | `*(uint32_t*)&plain[5]` (LE) | `<I @5` / `p[5..8]` LE | ✓ |
| 레코드 i | `&plain[9 + i*8]` | `p[9+8i : 17+8i]` | ✓ |
| mmolLx10 | `(b10<<2) \| (bf>>6)`, b10=r[7], bf=r[6] | `(r[7]<<2) \| (r[6]>>6)` | ✓ |
| trend | `(bf>>3) & 7` | `(r[6]>>3) & 7` | ✓ |
| remaining | `plain[len-2] \| plain[len-1]<<8` | 동일 | ✓ |
| 시각 | `startTime + i*60` | 동일 | ✓ |
| mg/dL | `round(mmolLx10*.1*convfactordL)`, convfactordL=18.0 | `round(mmolx10*1.8)` | ✓ |
| 저장 조건 | `hdr_index%5==0` | `index%5==0 && mmolx10>0` | 페이지는 0 을 추가로 버림 |

- Juggluco 는 값을 가공하지 않는다: `sens->savestream(eventTime,index,mgdL,…)` 로 그대로 저장하고, GS3 경로에서는 벤더 알고리즘(`process2/3`) 을 호출하지 않는다. temp/dump/c1/warn 비트 추출은 Juggluco 에서 주석 처리돼 있고(사용 안 함), 우리 파서의 해당 필드 식은 그 주석과 같다.
- 명령 빌더도 동일: 시간동기 0x03 = `06 03 <u32 LE> ck` (`v120_isec_update`, 시각은 `time(nullptr)` = UTC epoch), 활성화 0x0F = `06 0F <u32 LE> ck`, 인증 0x01 = `19 01 00 <MAC LE 6> <키 16> ck`. 페이지의 `now()` 도 UTC epoch 다.
- 파싱 코드 자체는 2026-07-03 에 Juggluco 저장소에 들어온 뒤 바뀐 적이 없다 (`git log -- sibionics3/`: 이후 커밋은 Java 연결 처리와 CN 판 siType 만 수정).
- Juggluco 의 GS3 NFC 처리(`Sib3Scan.java`) 는 NDEF **읽기**뿐이다 (transceive/write 없음). 즉 Juggluco 도 BLE 명령만으로 센서를 시작하며, 이 페이지의 handshake 는 Juggluco 와 동등하다. 10.9.2 변경 로그: "GS3 센서는 이전 버전에서는 공식 앱을 먼저 썼을 때만 동작했으나 이제 Juggluco 가 첫 앱이어도 동작" — 우리가 옮긴 소스는 그 이후 버전이다.
- juggluco.nl sensors 페이지(Juggluco 저자): "센서는 매분 값을 보내지만 5번은 같은 값이다", "index%5==0 인 값(60,65,70,…)만 보면 Juggluco 의 혈당값은 Sibionics 공식 앱과 같다". 즉 **이 비트 배치로 뽑은 값은 공식 앱과 대조 검증된 값**이고, 정상 동작에서도 값은 5분에 한 번만 바뀐다.

**결론:** 파서(오프셋·비트 위치·엔디안·단위 변환) 는 Juggluco 와 완전히 같고, Juggluco 저자가 그 결과를 공식 앱과 대조했다. 값이 "아예" 안 변한다면 파서가 아니라 다음 둘 중 하나다.

1. **센서가 보내는 r6/r7 바이트 자체가 고정** — 파서는 받은 대로 보여 주는 것. (센서 상태·활성화 문제)
2. **새 레코드가 저장되지 않아 화면이 마지막 값에 멈춤** — `mmolLx10=0` 필터, MTU 잘림이 같은 start 에서 반복, 연결 끊김 후 재연결 실패 등. 이 경우 화면의 "N분 전" 이 계속 커진다.

어느 쪽인지는 패킷 로그로만 구분된다. 확인 절차: 페이지의 **기록 내보내기** (저장된 모든 레코드를 원시 8바이트째로 로그 칸에 붙임. 새로고침해도 남아 있음) → **로그 복사** → 텍스트 파일 저장 → `python3 tools/gs3_log_analyze.py 로그.txt --all`. 스크립트는 `← FF31 wire …` 의 hex 와 내보내기 줄(`REC idx=… raw=…`, `READING idx=… mmolx10=…`) 을 다시 복호화·파싱해서 (1) 레코드별 전체 필드(r0–r7 원시 바이트 포함), (2) 필드별 변동 여부(각 바이트, u16 LE 후보 포함), (3) 판정(혈당 바이트 고정 / 전부 0 / 정상, 값이 바뀌는 index%5 위치, 빠진 index, MTU 잘림, 경고 비트) 을 출력한다. 페이지의 로그 보관 한도는 400줄 → 2000줄로 늘렸고, 모든 레코드의 원시 바이트를 `localStorage` (`gs3.raw`) 에 남기며, 경고 비트(gcwarn)는 화면과 표에 ⚠ 로 표시한다.

**웜업 후 첫 실기 레코드 (2026-09-11 21:47Z, 센서 시작 후 14시간 6분, 새로고침 직후 재연결):**

```
askNewData start=846 → 04 14 00 05 (result0/error5: 아직 없음) ×2, 8초 뒤 자발 push
13 14 01 4e 03 d4 76 a4 6a 80 56 8a 0b ca 5a 03 08 00 00 95
   count=1 startIndex=846 startTime=1789163220  rec = 80 56 8a 0b ca 5a 03 08
   r6=0b00000011 r7=0b00001000 → mmolLx10=32 (3.2 mmol/L, 58 mg/dL), trend=0, gcwarn(bit0)=1, bit1=1 (미명명)
   temp=346 (34.6 °C 로 해석하면 피부 온도로 자연스러움; 삽입 직후 317–319 → 14시간 후 346)
   fieldB=2954, fieldD=23242 (여전히 고정)
```

이 레코드는 파서가 Juggluco 와 같은 방식으로 정확히 풀린 것이며, 값 자체에 **센서가 gcwarn 경고 비트를 붙여** 보내고 있다. Juggluco 는 이 비트를 읽지 않고 58 mg/dL 로 그대로 표시한다. 경고 비트의 정확한 의미는 벤더 문서가 없어 [미확인] 이며, 이 값이 장시간 고정이라면 센서가 경고 상태의 값을 반복 송신하는 것으로 봐야 한다(채혈 측정과 대조 필요).

## 11.8 적대적 검증: 파서가 맞고 센서가 고정임을 증명 (2026-09-11, idx 846–868)

"Juggluco 와 같다" 는 "정답과 같다" 가 아니다. 그래서 값이 계속 3.2 mmol/L(58 mg/dL)로 고정된 실기 배치(index 846–868, 23개, 22분, 식사 포함)로 **반증 가설 "혈당은 실제로 변하는데 파서가 고정된 엉뚱한 바이트를 읽는다"** 를 직접 깼다. `python3 tools/gs3_log_analyze.py 로그.txt --adversarial` 로 재현된다.

방법: 레코드 8바이트(64비트)를 혈당으로 읽는 **모든** 방법(단일 바이트 8, 인접 u16 LE/BE 14, Juggluco 10비트 혈당·온도 필드)을 나열하고, 각 후보가 (a) 혈당 범위(40–400 mg/dL, 직접 또는 ×1.8)에 드는지 (b) 레코드마다 변하는지 (c) 식사 반응 크기(≥40 mg/dL 변동)를 내는지 집계했다.

| 관측 | 값 |
|---|---|
| 혈당 필드 `(r7<<2)\|(r6>>6)` | 23개 내내 **32 = 3.2 mmol/L = 58 mg/dL 고정** (r6=0x03, r7=0x08 어느 비트로 읽어도 고정) |
| 같은 패킷에서 변하는 바이트 | r0·r1(temp), r2(fieldB 하위), r4(fieldD 하위 비트) — **매분 새 값** |
| 시각 증가 | 레코드당 정확히 +60초 |
| 범위 안에서 변하는 유일한 후보 | 온도 `(r1<<2)\|(r0>>6)` = 335–354, 22분 스윙 19, 단조 드리프트 |
| 8바이트 통틀어 식사 반응(≥40 mg/dL) | **어떤 필드에도 없음** |

세 가지가 동시에 성립하므로 결론이 강제된다.

1. **파이프라인은 살아 있다.** 혈당이 고정된 바로 그 패킷들에서 temp·fieldB 가 매분 바뀌고, 타임스탬프가 +60 씩 증가하며, 체크섬이 통과한다. → 값 고정은 캐시/저장/파싱 정지 버그가 아니다(그런 버그면 temp 도 얼어야 한다).
2. **온도는 혈당이 아니다.** 온도를 혈당으로 읽으면 ×1.8(센서의 0.1 mmol 방식)에서는 603–637 mg/dL 로 전부 범위 밖이고, 직접 mg/dL 로 읽어야만 335–354 가 되는데 이는 34~35°C 대 피부 온도의 느린 드리프트(19의 단조 변동)이지 식후 곡선이 아니다. 게다가 혈당은 이미 r6/r7 에 있고 추세·경고 비트까지 그 안에서 자기일관하다.
3. **혈당 동역학이 없다.** 8바이트 어디를 혈당으로 읽어도 식사에 반응하는 필드가 하나도 없다. 정상 CGM 이 식사를 거치면 혈당 필드에 반드시 상승 곡선이 나와야 하는데, 64비트 전체에 그런 신호가 없다.

→ **파서는 정상이다**(범위·단위·비트배치가 자기일관하고, 고정 바이트에서 유효 혈당값을 내는 비트 조합은 Juggluco 의 것 하나뿐이다). 값이 안 변하는 것은 코드가 아니라 **센서가 3.2 mmol/L 에 gcwarn 경고 비트를 붙여 반복 송신** 하기 때문이다. 처음부터 2–4 mmol/L 저혈당대에서 시작해 3.2 로 수렴하고 식사에도 안 움직이며 매 레코드 gcwarn=1 인 것은, 실제 혈당을 추적하지 못하는 불량/미성숙 센서의 전형이다. 표시값을 실제 저혈당으로 판단하지 말고 채혈로 확인해야 한다(§12).

## 12. 유의사항

- Juggluco 는 **GPL-3.0** 이다. 코드를 그대로 가져오면 우리 앱도 GPL 이 된다. 이 문서와 `tools/gs3_protocol.py` 는 프로토콜 사실(상수·포맷·순서) 을 기술한 것이며, 상용 앱에는 클린룸으로 재구현할 것을 권장한다. 저자(j-kaltes) 는 "I don't help people with putting the code of Juggluco in their own app" 라고 명시 (Discussion #181).
- RC4 키와 앱 키는 벤더 앱 바이너리에서 추출된 값이다. 배포 시 법적 검토 필요.
- 계정 바인딩 때문에 **잘못된 ID 로 새 센서를 바인딩하면 공식 앱에서 못 쓴다.** 테스트는 버릴 센서 또는 공식 앱 계정 ID 로.
- 의료기기 데이터다. 표시 전 유효범위·웜업·경고 비트 처리를 넣어야 한다.

---

## 부록 A. 참고 링크

- Juggluco: https://github.com/j-kaltes/Juggluco (`Common/src/main/cpp/sibionics3/interpretgs3.cpp`, `Common/src/mobileSi/java/tk/glucodata/Si3GattCallback.java`)
- juggluco.nl 센서 문서: https://www.juggluco.nl/Juggluco/sensors , 계정 ID 도움말: https://www.juggluco.nl/Jugglucohelp/gs3number.html , 서버 조회: https://www.juggluco.nl/Jugglucohelp/SibionicsServer.html
- gluco-glance: https://github.com/mohasi/gluco-glance (GS1 평문 프로토콜, "newSI/GS3: different encrypted protocol")
- Juggluco Discussion #100 / #181, Issue #290 / #405, xDrip Discussion #3063 — 프로토콜 세부 없음
