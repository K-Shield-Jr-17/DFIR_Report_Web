# DFIR 메모리 포렌식 분석 보고서 (Snapshot 28)
**문서 번호:** IR-2026-0915-02  
**분석 대상:** `second/VICTIM_Windows-Snapshot28.vmem` (DESKTOP-IS00QJN)  
**분석 환경:** Volatility 3 (Framework 2.28.0)  
**작성 일자:** 2026년 9월 15일  

---

## 1. 개요 (Executive Summary)

피해 시스템 `DESKTOP-IS00QJN`의 메모리 스냅샷 28(`second/VICTIM_Windows-Snapshot28.vmem`)을 대상으로 Volatility 3 기반 메모리 정밀 포렌식을 수행하였습니다.

분석 결과, 시스템 내부에서 **정상 프로세스 위장 C2 비콘(`chrome.exe`) 실행**, **Unquoted Service Path 취약점을 이용한 로컬 권한 상승(`Updater.exe`)**, **내부 파일 서버(`192.168.60.20`) 대상 대규모 SMB(TCP 445) 측면 이동(Lateral Movement)** 행위가 식별되었습니다. 스냅샷 캡처 시점에 공격자는 SYSTEM 최고 권한의 C2 세션을 확보한 상태에서 파일 서버와 총 8개의 활성 SMB 세션을 유지하며 데이터 탐색 및 유출을 수행 중이었습니다.

---

## 2. 조사 환경 및 증거 제원

### 2.1 호스트 및 네트워크 정보
* **피해 호스트 (Victim):** `DESKTOP-IS00QJN`
  * IP 주소: `192.168.50.101` (외부/C2 대역), `192.168.60.101` (내부 도메인망)
  * 로그인 사용자: `CORP\employee01` (Session 2), 로컬 `Administrator` (Session 1)
* **공격자 C2 서버 (Kali):** `192.168.50.10:8080` (HTTP Listener)
* **도메인 컨트롤러 (DC):** `192.168.60.5`
* **파일 서버 (File Server):** `192.168.60.20` (공유자원: `\CompanyData`, `C$`)

### 2.2 메모리 증거 제원
* **메모리 파일:** `second/VICTIM_Windows-Snapshot28.vmem` (4,294,967,296 bytes)
* **메타데이터 파일:** `second/VICTIM_Windows-Snapshot28.vmsn` (4,313,112 bytes)
* **운영체제:** Windows 10 x64 (Build 15063)
* **메모리 수집 시각:**
  * **UTC:** `2026-09-15 18:22:58 UTC`
  * **KST:** `2026-09-16 03:22:58 KST` (UTC+9)
* **커널 베이스 (Kernel Base):** `0xf80074c08000`
* **디렉터리 테이블 베이스 (DTB / CR3):** `0x1ab000`

---

## 3. 공격 타임라인 (Timeline)

| 시각 (UTC) | 시각 (KST) | 주체 (PID) | 행위 내용 및 분석 의견 |
| :--- | :--- | :--- | :--- |
| **01:53:28** | **10:53:28** | `chrome.exe` (PID 432) | **초기 침투 및 Sliver C2 비콘 기동**<br>경로: `C:\Windows\Temp\Kisec\payloads\chrome.exe` |
| **01:53:28 ~** | **10:53:28 ~** | `chrome.exe` (PID 432) | **Kali C2 통신 수립**<br>`192.168.50.101:52953 → 192.168.50.10:8080` (ESTABLISHED) |
| **17:56:34** | **02:56:34** | `notepad.exe` (PID 7864) | 비콘 하위에서 `notepad.exe` 임시 생성 후 21초 뒤 종료 (`17:56:55 UTC`) |
| **18:00:27** | **03:00:27** | `Updater.exe` (PID 5552) | **Unquoted Service Path 악용을 통한 LPE 성공**<br>부모: `services.exe` (PID 668, SYSTEM 권한 획득)<br>가로챈 경로: `C:\Company\Updater.exe` |
| **18:00:27 ~** | **03:00:27 ~** | `Updater.exe` (PID 5552) | **권한 상승된 C2 비콘 세션 수립**<br>`192.168.50.101:52952 → 192.168.50.10:8080` (ESTABLISHED) |
| **18:00:27 ~** | **03:00:27 ~** | `Updater.exe` (PID 5552) | **내부 파일 서버로 측면 이동 (Lateral Movement)**<br>`192.168.60.101 → 192.168.60.20:445` (8개 SMB 세션 동시 유지) |
| **18:20:38** | **03:20:38** | `VSSVC.exe` (PID 4720) | 볼륨 섀도 복사본 서비스 기동 |
| **18:22:04** | **03:22:04** | `powershell.exe` (PID 3240)| Administrator 세션에서 PowerShell 실행 |
| **18:22:58** | **03:22:58** | **System** | **스냅샷 28 메모리 덤프 캡처 시점** |

---

## 4. 상세 기술 분석

### 4.1 초기 침투 및 C2 비콘 (ClickFix → Sliver Beacon)
* **프로세스 명:** `chrome.exe` (PID: **`432`**, PPID: `5176`)
* **실제 실행 경로:** **`C:\Windows\Temp\Kisec\payloads\chrome.exe`**
* **실행 인자 (CmdLine):** `"C:\Windows\Temp\Kisec\payloads\chrome.exe"`
* **분석 내용:**
  * 정상 Chrome 브라우저 경로(`C:\Program Files\Google\Chrome\Application\chrome.exe`)가 아닌 `C:\Windows\Temp\` 하위 디렉터리에서 실행된 전형적인 프로세스 마스커레이딩(T1036.005) 기법입니다.
  * 공격자의 Kali 리스너(`192.168.50.10:8080`)와 상시 연결 세션(`192.168.50.101:52953 ↔ 192.168.50.10:8080`, ESTABLISHED)을 맺고 비콘 통신을 지속하고 있었습니다.
  * `17:56:34 UTC`에 비콘 하위에서 `notepad.exe` (PID 7864)를 실행 후 종료시킨 행위가 확인되어, C2 콘솔을 통한 프로세스 실행 명령이 하달되었음을 입증합니다.

### 4.2 권한 상승 (Unquoted Service Path LPE)
* **프로세스 명:** `Updater.exe` (PID: **`5552`**, PPID: `668`)
* **부모 프로세스:** `services.exe` (`NT AUTHORITY\SYSTEM`)
* **취약 경로 (SCM 등록 경로):**
  ```
  C:\Company\Updater Apps\Apps\vulnapp.exe
  ```
* **실제 실행된 바이너리:**
  ```
  C:\Company\Updater.exe
  ```
* **취약점 분석 (T1574.009):**
  * 서비스 바이너리 경로 내에 공백(`Updater Apps`)이 존재함에도 불구하고 큰따옴표(`""`) 처리가 누락되어 있었습니다.
  * Windows SCM(서비스 제어 관리자)의 실행 파일 탐색 알고리즘에 의해, 공백 이전의 `C:\Company\Updater.exe`가 최우선으로 탐색되어 실행되었습니다.
  * 공격자가 비콘을 통해 `C:\Company\Updater.exe` 위치에 악성 Sliver 페이로드를 사전에 배치함으로써, 서비스 기동과 동시에 `NT AUTHORITY\SYSTEM` 권한을 획득하였습니다.

### 4.3 파일 서버 측면 이동 (Lateral Movement to File Server)
* **프로세스 명:** `Updater.exe` (PID: **`5552`**, SYSTEM)
* **행위 내용:**
  * 권한 상승에 성공한 `Updater.exe`는 Kali C2 서버와 상승된 제어 채널(`192.168.50.101:52952 ↔ 192.168.50.10:8080`, ESTABLISHED)을 개설했습니다.
  * 이어서 내부 파일 서버(`192.168.60.20:445`, SMB)를 대상으로 **총 8개의 TCP 세션을 동시에 ESTABLISHED 상태로 유지**하며 대규모 측면 이동을 감행했습니다.
* **네트워크 연결 세부 정보:**
  ```
  192.168.60.101:51663 -> 192.168.60.20:445 (ESTABLISHED)
  192.168.60.101:51541 -> 192.168.60.20:445 (ESTABLISHED)
  192.168.60.101:51606 -> 192.168.60.20:445 (ESTABLISHED)
  192.168.60.101:51487 -> 192.168.60.20:445 (ESTABLISHED)
  192.168.60.101:51550 -> 192.168.60.20:445 (ESTABLISHED)
  192.168.60.101:51531 -> 192.168.60.20:445 (ESTABLISHED)
  192.168.60.101:51671 -> 192.168.60.20:445 (ESTABLISHED)
  192.168.60.101:51653 -> 192.168.60.20:445 (ESTABLISHED)
  ```
  다중 SMB 세션은 파일 서버의 기밀 공유 폴더(`\CompanyData`) 또는 관리자 공유(`C$`)에 접근하여 파일 목록 열람, 데이터 복사 및 악성 파일 전파가 적극적으로 진행 중이었음을 의미합니다.

---

## 5. 침해 지표 (Indicators of Compromise - IoCs)

| 분류 | 유형 | 지표 값 (Value) | 상세 내용 |
| :--- | :--- | :--- | :--- |
| **File** | File Path | `C:\Windows\Temp\Kisec\payloads\chrome.exe` | 위장된 초기 침투 Sliver 비콘 |
| **File** | File Path | `C:\Company\Updater.exe` | LPE 권한 상승용 악성 바이너리 |
| **Network** | IP:Port | `192.168.50.10:8080` (TCP) | 공격자 Kali C2 서버 및 리스너 |
| **Network** | IP:Port | `192.168.60.20:445` (TCP) | 내부 파일 서버 대상 SMB 공격 트래픽 |
| **Vulnerability** | Service Path | `C:\Company\Updater Apps\Apps\vulnapp.exe` | 따옴표 누락 취약 서비스 경로 |
| **Process** | Process Name | `chrome.exe` (PID 432) | 악성 비콘 프로세스 |
| **Process** | Process Name | `Updater.exe` (PID 5552) | SYSTEM 권한 상승 C2 프로세스 |

---

## 6. 결론 및 대응 방안 (Recommendations)

스냅샷 28 메모리 분석을 통해 피해 호스트는 이미 완전하게 장악되었으며, 파일 서버로의 2차 침해가 발생 중임이 확인되었습니다. 다음 대응 조치가 즉시 요구됩니다.

1. **즉각적인 네트워크 격리:**
   * 피해 호스트 `DESKTOP-IS00QJN`(`192.168.50.101`, `192.168.60.101`) 망 분리 및 스위치 포트 차단
2. **악성 프로세스 종료 및 파일 영구 삭제:**
   * PID 432(`chrome.exe`), PID 5552(`Updater.exe`) 즉시 종료
   * `C:\Windows\Temp\Kisec\` 디렉터리 및 `C:\Company\Updater.exe` 파일 영구 삭제
3. **취약 서비스 설정 시정:**
   * 취약 서비스의 레지스트리 경로에 따옴표(`"`)를 추가하여 재악용 방지:
     `"C:\Company\Updater Apps\Apps\vulnapp.exe"`
4. **자격 증명 강제 재설정:**
   * 메모리 덤프 행위(LSASS)가 수반된 침해 사고이므로, 도메인 사용자(`CORP\employee01`) 및 호스트 로컬 관리자 패스워드 즉시 일괄 변경
5. **파일 서버 침해 흔적 전수 조사:**
   * 파일 서버(`192.168.60.20`)의 Windows 보안 이벤트 로그(EID 5140, 5145)를 분석하여 `192.168.60.101`로부터 열람/다운로드된 파일 목록 및 유출 규모 확인
