# Autoruns ARN Before/After 레지스트리 관련 비교 보고서

## 1. 결론

`Before.arn`과 `After.arn`은 모두 Sysinternals Autoruns의 OLE Compound Binary 저장 파일이다. 내부 `Header` 스트림은 두 파일 모두 `Autoruns`, 형식 버전 `7`이며, 각각 1,479개 Autoruns 항목을 포함한다.

두 파일의 Autoruns 논리 데이터는 완전히 동일하다. 총 15,671개 스트림(항목 데이터 스트림 15,668개와 전역 `Header`/`SmallIcons`/`LargeIcons` 스트림)의 내용이 모두 일치하며, 추가·삭제·변경된 Autoruns 항목은 **0건**이다. 따라서 이 자료만으로는 ClickFix, Sliver C2 beacon, Unquoted Service Path LPE, LSASS dump 또는 File Server lateral movement와 연결되는 레지스트리 변경 증적을 확인할 수 없다.

파일 전체 SHA-256은 다르지만, 차이는 OLE 컨테이너의 저장 시각 메타데이터에만 존재한다. 이를 레지스트리 키 수정 시각이나 침해 행위 시각으로 해석해서는 안 된다.

## 2. 파일 식별 및 무결성

| 구분 | Before.arn | After.arn |
|---|---|---|
| 파일 크기 | 6,327,804 bytes | 6,327,804 bytes |
| SHA-256 | `B839DB639641C0AFE23C708FB3FEEC58594F62665008DEFF6BE206C4768C7ADC` | `E196B1E2F463F0160D6713CBC5E794A18D9B7ECA2065DAD28526373FA623FE23` |
| 파일 시그니처 | `D0 CF 11 E0 A1 B1 1A E1` | `D0 CF 11 E0 A1 B1 1A E1` |
| 실제 형식 | OLE Compound Binary 기반 Autoruns `.arn` | OLE Compound Binary 기반 Autoruns `.arn` |
| 내부 헤더 | `Autoruns`, version 7 | `Autoruns`, version 7 |
| Autoruns 항목 수 | 1,479 | 1,479 |

## 3. 변경 Finding

| Finding | 레지스트리 키/값 | Before 값 | After 값 | 시간정보 | 의미/침해 연관성 |
|---|---|---|---|---|---|
| 확인된 레지스트리 관련 변경 없음 | 해당 없음 | 1,479개 항목 | 동일한 1,479개 항목 | 각 항목의 내장 `TimeStamp`도 모두 동일 | 서비스 등록·변경, 로그온 지속성, 이미지 하이재킹 등 Autoruns가 수집한 범위에서 시나리오 연관 변경을 입증할 수 없음 |

## 4. 우선 검토 영역

| 검토 영역 | 비교 결과 | 해석 |
|---|---:|---|
| 서비스 및 드라이버 | 변경 0건 | 신규 서비스, 서비스 실행 경로 변경 또는 새 Unquoted Service Path가 두 캡처 사이에 도입되었다는 증거 없음 |
| Run / RunOnce 및 기타 Logon ASEP | 변경 0건 | ClickFix 이후 로그온 지속성 등록 증거 없음 |
| Winlogon | 변경 0건 | `Shell`, `UserInit` 등 Autoruns 수집 범위에서 변경 없음 |
| IFEO / Image Hijacks | 변경 0건 | 디버거 기반 이미지 하이재킹 변경 없음 |
| AppInit | 변경 0건 | `AppInit_DLLs` 관련 변경 없음 |
| Defender 관련 Autoruns 항목 | 변경 0건 | Defender 서비스·드라이버·알림 항목은 동일함. 단, Defender 정책/예외 전체를 수집한 자료는 아님 |
| PowerShell 문자열 | 시나리오성 변경 0건 | 확인된 `PowerShell` 문자열은 양쪽에 동일한 표준 Hyper-V PowerShell Direct 서비스 설명뿐임 |
| LSASS 문자열 | 시나리오성 변경 0건 | 양쪽에 동일한 Windows 기본 서비스 참조만 존재하며, LSASS 덤프 실행 증거가 아님 |
| 네트워크·공유·사용자 | 판정 불가 | `LanmanServer` Autoruns 항목은 동일하지만, ARN은 공유·사용자·원격 접속 흔적 전체를 수집하는 포맷이 아님 |
| `Sliver`, `DESKTOP-IS00QJN` 정확 문자열 | 양쪽 모두 0건 | 문자열 부재만으로 행위 부재를 입증할 수 없음 |

## 5. 시간정보

| 메타데이터 | Before | After | 증거 해석 |
|---|---|---|---|
| OLE Root 저장 메타데이터 | 2026-09-15 00:37:02.338 UTC / 09:37:02.338 KST | 2026-09-15 02:25:33.866 UTC / 11:25:33.866 KST | ARN 컨테이너 저장 시각 성격; 레지스트리 키 수정 시각이 아님 |
| Autoruns 항목 `TimeStamp` | 모든 항목에서 After와 동일 | 모든 항목에서 Before와 동일 | 항목 수준의 변경 없음 |

## 6. 한계 및 후속 증적

Autoruns `.arn`은 자동 시작 지점(ASEP) 중심 자료이며 전체 레지스트리 스냅샷이 아니다. 따라서 이번 비교 결과는 “두 ARN의 Autoruns 항목이 동일하다”는 뜻이며, 시나리오의 행위가 발생하지 않았다는 뜻은 아니다. 다음 자료를 별도로 확보해야 한다.

- `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, 각 사용자 `NTUSER.DAT` 및 `UsrClass.dat` 하이브
- 서비스 생성/변경 확인을 위한 System 이벤트 로그(특히 Service Control Manager)
- PowerShell Operational, Defender Operational, Security, Sysmon 로그
- Prefetch, Amcache, Shimcache, SRUM, LNK/Jump List 및 브라우저/다운로드 흔적
- LSASS 접근·덤프 및 원격 이동 확인을 위한 EDR/Sysmon 프로세스·파일·네트워크 이벤트
- 파일 서버 측 로그온, SMB 공유 접근 및 객체 접근 로그

## 7. 최종 판단

**확인된 변경 Finding: 0건.** 두 파일의 해시 차이는 Autoruns 데이터 변경이 아니라 OLE 저장 메타데이터 차이에서 발생했다. 현재 자료만으로 시나리오 단계와 직접 연결되는 레지스트리 증적을 보고서에 기재해서는 안 된다.
