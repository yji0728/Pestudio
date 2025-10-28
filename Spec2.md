아래 스펙은 “PE 파일(Windows 실행 파일)을 격리된 가상 샌드박스에서 실행하고, Procmon으로 동작 전반을 추적·로깅하며, 생성 파일/프로세스를 덤프하고(메모리/디스크), API 호출·레지스트리 변경을 별도 로그로 정리, VirusTotal API 결과까지 통합”하는 도구의 설계 명세입니다. CLI와 GUI를 모두 제공합니다. 안전한 연구·분석 목적을 전제로 하며, 실제 운영 시 반드시 네트워크·시스템 격리를 지켜주세요.

1) 목표와 범위
- 목표
  - 임의의 PE 파일을 샌드박스(Windows VM)에서 자동 실행하여 행위 기반 추적
  - Sysinternals Procmon 기반의 파일/레지스트리/프로세스/네트워크 이벤트 수집
  - 생성 파일 수집, 신규 프로세스 메모리 덤프(Procdump 등 활용)
  - API 호출 수준의 가시성(ETW/추가 로깅으로 상위 수준 호출 흐름 집계)
  - VirusTotal v3 API로 해시 조회/분석 제출/리포트 취합
  - CLI와 GUI 모두에서 일관된 워크플로 제공, 결과 아카이브/리포팅
- 비목표
  - 안티-VM/안티-분석 우회 기법 제공 X
  - 커널 드라이버 개발 상세, 저수준 API 후킹 구현 가이드 X
  - 실서비스 맬웨어 배포/테스트 목적 X

2) 아키텍처 개요
- 상위 구성
  - Host Orchestrator(호스트): 실행 요청 관리, VM 오케스트레이션, 결과 취합/리포팅, CLI/GUI 제공
  - VM Manager(호스트): Hyper-V/VMware/VirtualBox 중 택1 연동, 스냅샷 관리, 파일 주입/회수
  - Guest Agent(게스트): 샌드박스 내 경량 에이전트. Procmon/Procdump/수집 스크립트 실행, 종료/정리
  - Instrumentation(게스트): Procmon, Procdump, 네트워크 캡처(선택), ETW 기반 보조 이벤트 캡처
  - Analysis Pipeline(호스트): PML→CSV/JSON 변환, 정규화 스키마로 적재, 상관분석, 요약/탐지 룰
  - VirusTotal Client(호스트): 해시 조회→미존재 시 제출→분석 상태 폴링→요약 반영
  - Storage: 러닝 결과/이벤트/아티팩트/리포트 저장(로컬 디스크 + SQLite/PostgreSQL)
- 데이터 플로우
  1. 사용자가 PE 업로드→분석 요청
  2. VM 스냅샷 클론/부팅→에이전트 기동→도구(Procmon 등) 주입
  3. Procmon 캡처 시작→샘플 실행→프로세스 트리 모니터링/덤프/파일 수집
  4. 타임아웃/종료→Procmon stop→로그/아티팩트 회수
  5. PML 변환/정규화→요약 생성
  6. VT 해시 조회/제출→결과 병합
  7. 최종 리포트 생성→GUI/CLI에서 조회/내보내기

3) 안전 가이드·운영 전제
- 네트워크 격리: 기본 오프라인 또는 INetSim(옵션) 같은 가짜 서비스로 샌드박스 내 가짜 인터넷 제공
- 스냅샷 복원: 매 러닝 후 VM 즉시 revert
- 제한 계정: 샘플은 표준 권한 사용자로 실행
- 시간 제한: 기본 3~5분(설정 가능), soft stop→graceful 종료→hard kill 순
- EULA 및 라이선스: Sysinternals 도구 /AcceptEula 플래그 사용, VT TOS 준수
- 민감정보 차단: 공유폴더 읽기/쓰기 최소화, 호스트 경로 마스킹, 아티팩트 자동 백업/검증

4) 컴포넌트 명세

4.1 Host Orchestrator
- 기능: 실행 요청 수신, 러닝 ID 발급, VM 생명주기 제어, 결과 집계, 리포트 생성
- 기술 제안: C# .NET 8 서비스(Windows), REST 내부 API(로컬 전용), Serilog 로깅
- 책임: CLI/GUI 공용 백엔드, 설정 관리(config.json + 암호화된 비밀값)

4.2 VM Manager
- Hypervisor 선택
  - Hyper-V: Production 환경 권장, PowerShell 모듈(Core: Hyper-V) 활용
  - VMware Workstation Pro: vmrun, VIX API
  - VirtualBox: VBoxManage
- 기능: 스냅샷 클론/부팅/중지/revert, 파일 주입(게스트 도구/공유폴더), 커맨드 실행
- 보안: 네트워크 스위치 격리, 스냅샷 태깅, 리소스 제한(CPU/메모리/시간)

4.3 Guest Agent
- 역할: Procmon/Procdump/수집 스크립트 실행 및 상태 리포트
- 통신: 호스트→게스트(명령), 게스트→호스트(상태/아티팩트) 양방향. 하이퍼바이저 통합채널 또는 내부 REST+TLS(로컬)
- 기능
  - Procmon 비대화식 캡처 시작/종료/백업
  - 샘플 실행(표준 계정, 환경변수/워크디렉토리/인자 전달)
  - 프로세스 트리 모니터링(ETW/WMI)
  - 신규 프로세스 메모리 덤프 트리거(Procdump)
  - 생성 파일 목록 수집 및 아카이브
  - 종료/정리(결과 패키징)

4.4 Instrumentation(게스트)
- Procmon Controller
  - 시작: Procmon64.exe /AcceptEula /Quiet /BackingFile C:\capture\run.pml
  - 종료: Procmon64.exe /Terminate
  - 변환: Procmon64.exe /OpenLog C:\capture\run.pml /SaveAs C:\capture\run.csv
  - 필터 전략: 실행 전 광범위 캡처→사후 프로세스 트리 기반 후처리 필터링(정확성/안정성 우선)
- Process/ETW Watcher
  - 프로세스 생성/종료 이벤트 수집(ETW 또는 WMI)
  - 트리 상관: 루트 PID부터 자식 PID 묶음
- Procdump Controller
  - 대상: 루트/자식 프로세스 생성 시점 또는 종료 전
  - 모드: -ma(풀 메모리) 기본, 크기 제한/예외 처리 옵션
- 파일/레지스트리/네트워크
  - 파일·레지스트리: Procmon 이벤트 기반 후처리로 분류/요약
  - 네트워크: 기본은 Procmon 이벤트 요약, 옵션으로 pcap(WinPcap/Npcap) 연동
- API 호출 가시성
  - 저수준 후킹 대신 ETW/고수준 이벤트(프로세스/파일/레지스트리/네트워크)로 호출 흐름 재구성
  - 선택: 별도 플러그인으로 API 모니터링(고급) 모듈화 가능(기본 비활성)

4.5 Analysis Pipeline(호스트)
- PML→CSV→정규화(JSON) 변환
- 정규 스키마
  - Event(event_id, run_id, timestamp, process_guid, process_name, pid, category[file/registry/process/network], op, path/registry_key/destination, result, detail)
  - Process(process_guid, parent_guid, image_path, cmdline, first_seen, last_seen)
  - Artifact(artifact_id, run_id, type[file|dump|pcap|log], path, hash)
  - Run(run_id, sample_hashes, start/end, verdict, vt_summary)
- 상관 분석
  - 프로세스 트리 묶기, 파일 생성→실경로 해시 계산, 레지스트리 변경 요약, 네트워크 목적지 요약
- 요약/탐지
  - 히트카운트: 삭제/영구쓰기/서비스등록/자동실행 키/스크립트 드롭/암호화 API 패턴 등
  - 간단한 ATT&CK 매핑(고레벨)

4.6 VirusTotal Client
- 흐름
  - SHA-256 계산→/files/{hash} 조회
  - 미존재 시 업로드→/analyses/{id} 폴링(레이트 제한 고려)
  - 엔진별 탐지 카운트, 분류 요약, 링크 저장
- 안전장치: 비공개 제출 옵션, 파일 사이즈 제한, 요청 간 backoff

4.7 Storage
- 로컬 아카이브 구조(호스트)
  - runs/{run_id}/
    - raw/run.pml
    - raw/run.csv
    - normalized/events.jsonl
    - artifacts/files/…
    - artifacts/dumps/…
    - artifacts/network/run.pcap (옵션)
    - reports/summary.json
    - reports/report.html
- DB: SQLite(단일 호스트) 또는 PostgreSQL(다중 호스트)

5) 실행 플로우(러닝 단위)
- 준비
  - 스냅샷 베이스: 최신 패치 적용, 표준 사용자 계정, 게스트 에이전트/도구 사전 배치
- 단계
  1. 호스트에 샘플 업로드 → 해시 계산
  2. VM 스냅샷 클론/부팅 → 에이전트 건강검진
  3. Procmon 캡처 시작(백킹파일 지정)
  4. 프로세스 트리 모니터 시작(ETW/WMI)
  5. 샘플 실행(인자/워킹디렉토리 반영)
  6. 러닝 중
     - 자식 프로세스 이벤트 수집
     - 프로세스 생성 시 Procdump 트리거(정책에 따라 최초 n개, 크기 제한)
     - 생성 파일 목록 수집(잠금 해제 대기/종료 후 복사)
  7. 타임아웃 또는 종료 감지
  8. Procmon 종료 → PML→CSV/JSON 변환
  9. 아티팩트 회수(파일/덤프/pcap)
  10. 분석 파이프라인 실행(정규화/요약/탐지)
  11. VirusTotal 조회/제출/요약 병합
  12. 결과 리포트 생성 및 보관
  13. VM revert

6) 로그/아티팩트 설계
- 분리 로그
  - file_events.jsonl, registry_events.jsonl, process_events.jsonl, network_events.jsonl
  - api_flow.jsonl(옵션, 상위 수준 흐름 요약)
- 아티팩트
  - files/: 생성/드롭된 파일 원본+해시 목록
  - dumps/: 각 PID별 .dmp, 메타정보(JSON)
  - pcap(옵션): run.pcap
- 요약 리포트
  - 개요: 해시, VT 탐지율, 실행 시간, 프로세스 개요
  - 주요 행위: 시작 프로그램 등록, 서비스 설치, UAC 우회 시도 등 히트리스트
  - 프로세스 트리 시각화
  - 타임라인(분류별 이벤트 밀도)

7) CLI 명세
- 바이너리: sandscope.exe (예시)
- 공통 옵션
  - --config path, --vm <id>, --timeout <sec>, --net offline|inetsim|bridged, --vt on|off
- 주요 명령
  - analyze start <path> [--args "..."] [--working-dir ...] [--dump all|root|none] [--pcap on|off]
  - analyze status <run_id>
  - analyze fetch <run_id> --artifact all|files|dumps|logs --out <dir>
  - analyze report <run_id> --format html|json --open
  - vt check <path|sha256>
  - vt submit <path> [--private]
  - runs list | runs show <run_id> | runs purge <filter>
- 예
  - sandscope analyze start sample.exe --args "-silent" --dump root --timeout 240 --vt on

8) GUI 명세
- 기술: WPF(.NET 8) 또는 WinUI 3
- 주요 화면
  1. 대시보드
     - 최근 러닝, 상태(진행/완료/실패), 큐, VT API 상태
  2. 새 분석 실행 모달
     - 파일 선택, 인자/워크디렉토리, 타임아웃, 네트워크 모드, 덤프 정책
  3. 러닝 상세
     - 헤더: 해시/VT 요약/타이머/상태
     - 탭
       - Timeline: 시간축에 이벤트 밀도
       - Process Tree: 트리/노드 클릭→세부 이벤트 필터
       - Files: 생성/수정/삭제, 해시, 크기, 내보내기
       - Registry: Key/Value 변경, 자동실행 키 강조
       - Network: 도메인/IP/포트/프로토콜 요약
       - API Flow(옵션): 상위 수준 호출 흐름 묶음
       - Dumps: PID별 덤프 다운로드, 크기/시간
       - Logs: 원시 CSV/JSON 다운로드
  4. 리포트 보기/내보내기
     - HTML/PDF/JSON
- UX
  - 프로세스 트리-연동 필터(다중 선택)
  - 고급 필터 저장/불러오기
  - 위험 신호 배지(색상/아이콘)

9) 구성/배포
- 빌드: .NET 8 단일 파일 배포 옵션
- 설치: MSI/Zip 포터블. Sysinternals 툴 포함 시 라이선스 표기
- 설정
  - config.json
    - hypervisor: hyperv|vmware|virtualbox
    - vm: base_vm_id, snapshot_name
    - network: mode, inetsim_addr(옵션)
    - vt: api_key, private_submit, rate_limit
    - dump: max_per_run, full_dump(true/false)
    - timeout: default_seconds
- 권한: 호스트 관리자 권한(하이퍼바이저 제어), 게스트 표준 사용자

10) 테스트 전략
- 유닛: 파서/정규화/요약 로직
- 통합: VM 오케스트레이션, Procmon 캡처→변환→상관
- 시나리오
  - 정상 PE(메모장) 실행→파일/레지스트리 변화 최소
  - 파일 생성/삭제 이벤트 유도 샘플
  - 자식 프로세스 스폰/종료 확인
  - 타임아웃/강제 종료 경로
  - VT 없는 샘플(업로드→폴링)
- 회귀: 대용량 이벤트(> 수백만 라인) 처리 성능/안정성

11) 성능·확장·보안
- 성능
  - Procmon 백킹파일 로테이션/최대 크기 제한 옵션
  - 변환 파이프라인 스트리밍 처리(JSONL)
  - 멀티런 큐잉: VM 풀을 N대로 확장
- 보안
  - 샌드박스 오프라인 기본, 필요 시 프록시/시뮬레이션
  - 에이전트 통신 TLS, 일회성 토큰
  - 결과 아티팩트 무해화: 자동 Zip+마커, 더블클릭 방지
- 감사
  - 모든 조작(시작/중지/가져오기) 감사 로그 남김

12) 기술 스택 제안
- 주언어: C# .NET 8
- GUI: WPF
- 로그/파이프라인: Serilog + System.Text.Json
- DB: SQLite(기본) → PostgreSQL(확장)
- 하이퍼바이저: Hyper-V(Windows 네이티브)
- 도구: Procmon, Procdump, Npcap(옵션), 7-Zip(아카이브)
- 대안(원한다면): Python(typer+PySide)/Go(컴팩트 CLI), 단 Windows 통합성은 .NET이 우수

13) 운영 정책(권장 기본값)
- 타임아웃: 240초
- 네트워크: offline
- 덤프: root+첫 자식 3개, 크기 1.5GB 이하
- Procmon: 파일/레지스트리/프로세스/네트워크만, 드라이버/프로파일링 제외
- VT: 조회 우선, 미존재 시 비공개 업로드

14) 간단 명령 시퀀스(참고)
- 게스트 내부
  - Procmon 시작: Procmon64.exe /AcceptEula /Quiet /BackingFile C:\capture\run.pml
  - 샘플 실행: start "" "C:\path\sample.exe" [args]
  - 종료: Procmon64.exe /Terminate
  - 변환: Procmon64.exe /OpenLog C:\capture\run.pml /SaveAs C:\capture\run.csv
  - 프로세스 덤프: procdump64.exe -ma <pid> C:\capture\dumps\pid_<pid>.dmp
- 호스트
  - 파일 주입/회수: 하이퍼바이저 게스트 도구 또는 공유폴더
  - VT: v3 REST 호출(files/{hash}, analyses/{id})

15) 향후 확장
- 샌드박스 OS 프로필 다중화(Win10/Win11/서버)
- 스냅샷 자동 업데이트 파이프라인
- 규칙 엔진(YARA on files/dumps, Sigma 변환)
- MITRE ATT&CK 매핑 강화·시각화
- REST API 공개 및 팀 협업 기능

질문으로 마무리할게요. 환경과 요구를 더 정확히 맞추면 스펙을 세밀화할 수 있어요.
- 어느 하이퍼바이저를 선호하시나요? Hyper-V, VMware, VirtualBox 중 하나를 고르실 수 있나요?
- 샌드박스 네트워크는 기본 오프라인으로 두고, INetSim 같은 가짜 인터넷을 옵션으로 두는 구성이 괜찮을까요?
- 프로세스 메모리 덤프는 모든 자식 프로세스까지 수집할까요, 아니면 선택(루트+상위 n개)으로 제한할까요?
- VirusTotal은 조회만(해시 존재 시)으로 제한할지, 미존재 시 자동 업로드까지 진행할까요?
- GUI는 WPF(.NET) 기반으로 Windows 전용을 선호하시는지, 아니면 다른 UI 스택을 원하시나요?

원하시면 이 스펙을 기반으로 작업 항목(백로그)과 마일스톤, 구체 UI 와이어프레임, 설정 템플릿 샘플까지 정리해드릴게요.
