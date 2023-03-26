---
title: 'Threat Hunting: Detecting APT37 TTPs'
date: 2023-03-26 16:58:13
category: 'threat_hunting'
draft: false
---


APT37은 최소 2012년부터 활동한 그룹으로 다양한 공격 방식을 사용해온 그룹입니다. 

본 글에서는 APT37의 여러 위협 활동 중 최근(21년) 일어난 개인PC를 타겟으로 정보를 탈취하는 행위에 사용한 공격방식을 시뮬레이션 하고 해당 위협을 탐지하는 방법에 대해 설명합니다. (APT37 그룹 고유의 위협 및 특징을 탐지하기보다는, 범용적인 TTP를 탐지하는 것에 목적을 두고 있습니다.)

악성코드 샘플을 수집하지 못한 관계로 오로지 APT37 분석 리포트들만을 참고하여 위협을 모사했습니다. 하지만 제가 임의로 특정 Technique을 추가하거나 제외한 부분도 있습니다. 

> 예시로 APT37은 악성 워드 문서 내에서 C2서버로부터 추가 악성 매크로를 로드하는 방식을 사용했지만, 본 글에서는 C2서버로부터 추가 악성 매크로가 아닌 CVE-2022-30190 취약점이 사용된 HTML파일을 다운로드해 실행하는 방식을 사용합니다.
> 

**실제 APT37의 공격 시나리오와 100% 같지 않다는 점을 유념해 주셨으면 합니다.**





### [TOC]


- [Threat Hunting: Detecting APT37 TTPs](#threat-hunting--detecting-apt37-ttps)
- [1. APT37](#1-apt37)
  * [A. 공격 조직과 타겟](#a----------)
  * [B. 침투 방식](#b------)
- [2. 공격 시나리오](#2--------)
  * [A. 공격 시나리오 상세 설명](#a--------------)
  * [B. 시나리오 시뮬레이션 방법](#b--------------)
- [3. 탐지](#3---)
  * [A. 탐지 플랫폼](#a-------)
  * [B. 1차 탐지](#b-1----)
  * [C. 2차 분석/탐지](#c-2-------)
- [4. 참고](#4---)






# 1. APT37



## A. 공격 조직과 타겟

APT37은 북한 추정 해커조직으로 2012년부터 국내를 대상으로 공격 활동을 지속하고 있으며, 공격 조직이 속한 국가와 관련된 국내 주요 인사들이 공격 대상입니다. 침해한 시스템을 파괴하거나 탈취한 정보를 이용한 협박 등의 행위를 하지 않는 것으로 보아 감시 목적이 강한 것으로 추정됩니다.

## B. 침투 방식

타겟이 관심을 가질 만한 내용으로 스피어피싱 이메일을 송부하여 악성코드를 다운로드 받도록 유도합니다. 

![[https://industrialcyber.co/threat-landscape/securonix-provides-details-on-konni-malware-campaign-striking-high-value-eu-targets/](https://industrialcyber.co/threat-landscape/securonix-provides-details-on-konni-malware-campaign-striking-high-value-eu-targets/)](Threat_Hunting_Detecting_APT37_TTPs\Untitled.png)



# 2. 공격 시나리오

먼저 APT37 공격 시나리오를 요약해서 설명하겠습니다.

APT37은 악성 워드 문서를 통해 시스템에 침투합니다. 이후 다양한 Defense Evasion 테크닉을 사용하여 악성 DLL을 윈도우 정상 프로그램에 로드하여 실행합니다. 악성 DLL은 시스템에 상주해 주기적으로 정보를 탈취하여 C2로 전송하는 역할을 합니다. 

자세한 설명은 바로 다음 파트에서 이어지며, 시나리오 설명을 위해 ATT&CK Matrix를 사용합니다. 전체적인 ATT&CK Matrix 매핑 정보는 다음과 같습니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled1.png)



## A. 공격 시나리오 상세 설명

ATT&CK Matrix 를 사용해 공격 시나리오를 설명합니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled2.png)

### (1) Compromise Infrastructure: Server([T1584.004](https://attack.mitre.org/techniques/T1584/004/)) & Stage Capabilities: Upload Tool([T1608.002](https://attack.mitre.org/techniques/T1608/002/)) & Develop Capabilities: Malware([T1567.001](https://attack.mitre.org/techniques/T1567/001/))

공격자는 기업의 웹서버를 탈취해 명령제어 서버를 구축하며 공격에 필요한 문서, 스크립트, 악성코드를 자체 제작합니다. 분석 리포트에 따르면 공격자는 탈취한 페이스북 계정을 사용하여 공격 대상에게 접근했음을 알 수 있습니다.  본 글에서는 [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) 과 [Resource Development](https://attack.mitre.org/tactics/TA0042/) Tactic 부분은 시뮬레이션 하지 않습니다.

### (2) Phishing: Spearphishing Attachement([T1566.001](https://attack.mitre.org/techniques/T1566/001/))

공격자는 비밀번호로 암호화된 악성 RAR 파일과 함께 스피어 피싱 메일을 송부합니다. 

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled3.png)

### (3) User Execution: Malicious File([T1204.002](https://attack.mitre.org/techniques/T1204/002/))

rar파일이 해제되면 정상 파일로 위장된 악성 word문서가 생성됩니다. 

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled4.png)

### (4) Exploitation for Client Execution([T1203](https://attack.mitre.org/techniques/T1203/))

공격자는 CVE-2022-30190 취약점이 사용된 악성 워드 문서를 통해 서버로부터 Powershell 커맨드를 다운로드해 실행시킵니다. 이 명령어는 작업 스케줄러 태스크를 생성합니다. 

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled5.png)

> **CVE-2022-30190** 이란 RCE 취약점으로 이를 활용하면 MS오피스 문서 내에서 TargetMode=”Exeternal”모드로 서버에서 html파일을 로드한 후 msdt url protocol을 사용하여 파워셸 명령어를 실행할 수 있습니다. 
타겟 유저가  “매크로 허용”을 클릭하지 않아도, 악성 행위 수행이 가능합니다. 
자세한 설명은 [링크](https://www.cybereason.com/blog/threat-alert-follina/msdt-microsoft-office-vulnerability)를 참고해 주세요.

### (5) Scheduled Task/Job: Scheduled Task([T1053.005](https://attack.mitre.org/techniques/T1053/005/))

취약점을 활용해 시스템에 작업 스케줄러 태스크를 생성 및 실행합니다. 생성된 태스크는 C2서버에 접속을 시도합니다.

### (6) Masquerading([T1036](https://attack.mitre.org/techniques/T1036/))

작업 스케줄러 등록 시 정상 태스크로 위장하기 위해 특정 백신사명을 사용합니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled6.png)

### (7) System Binary Execution: Mshta([T1218.005](https://attack.mitre.org/techniques/T1218/005/))

등록된 작업 스케줄러 태스크가 실행되면, Windows의 정상 유틸리티인 mshta를 악용해 악성 .chm을 서버에서 다운로드하고 실행합니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled7.png)

### (8) System Binary Proxy Execution: Compiled HTML File([T1218.001](https://attack.mitre.org/techniques/T1218/001/))

실행된 .chm 파일은 도움말 파일로 위장한 악성 페이로드입니다.  .chm파일 실행 시 악성 페이지로 연결되어 추가 파워쉘 스크립트를 다운로드 받아 실행시킵니다.

.chm 파일 생성을 위해 컴파일에 사용된 HTML 파일은 [여기](https://github.com/hyunjungg/Threat-Hunting/blob/APT37/APT37/Resources/Compromised_Server/payloads/hello.chm.htm)서 확인하실 수 있습니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled8.png)

### (9) Command and Scripting Interpreter: Powershell([T1059.001](https://attack.mitre.org/techniques/T1059/001/))

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled9.png)

.chm 파일에 의해 다운로드 된 파워셸 스크립트는 C2서버와 통신 하며 다음과 같은 역할을 합니다.

- 감염된 시스템의 UUID 값 전송
  
    이 값이 C2서버에 전송되면, C2서버는 해당 UUID 값으로 서버의 특정 경로에 폴더를 생성합니다.
    
    이 폴더는 추후 감염 시스템에서 수집한 파일들과 스크린 샷을 저장하는 목적으로 사용됩니다.
    
- C2 서버에서 수신한 명령어 실행
  
    C2 서버로부터 명령어를 수신 받고 실행하고, 수행 결과를 다시 C2서버로 전송합니다.
    

### (10) System Time Discovery([T1124](https://attack.mitre.org/techniques/T1124/))

C2서버와 통신하는 파워셸 스크립트는 시스템의 시간 정보를 출력하는 커맨드를 실행하고 서버로 전송합니다.

### (11) Data Encoding: Non-Standard Encoding([T1132.002](https://attack.mitre.org/techniques/T1132/002/))

명령어 실행 결과를 XOR 암호화 후 C2서버에 전송합니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled10.png)

### (12) BITS Jobs([T1197](https://attack.mitre.org/techniques/T1197/))

(9)번에서 실행된 파워셸 스크립트는 BitsAdmin을 통해 악성 dll 파일을 다운로드합니다. 

### (13) Hijack Execution Flow: DLL Side Loading([T1574.002](https://attack.mitre.org/techniques/T1574/002/))

파워셸 스크립트는 악성 dll 파일 실행을 위해 정상 프로그램에 Side Loading 기법을 이용하여 악성코드를 주입합니다. 이로 인해 악성 dll이 Windows 정상 프로그램에 로드되어 실행됩니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled11.png)

### (14) Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder([T1547.001](https://attack.mitre.org/techniques/T1547/001/))

실행된 dll 파일은 지속적으로 정보를 탈취하기 위해 레지스트리에 자기 자신을 등록합니다.

등록 경로는 다음과 같습니다.

```bash
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### (15) Screen Capture([T1113](https://attack.mitre.org/techniques/T1113/)) & Automated Collection([T1119](https://attack.mitre.org/techniques/T1119/))

악성 dll은 피해자 화면을 지속적으로 캡처하고 C2서버에 전달합니다. C2서버로 전송 된 스크린 샷들은 (9)번에서 생성된 폴더에 저장됩니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled12.png)

### (16) Data from Local System([T1005](https://attack.mitre.org/techniques/T1005/))

감염 시스템내에서 `CSIDL_DESKTOP`, `CSIDL_PERSONAL`,`CSIDL_MYMUSIC`, `CSIDL_MYVIDEO` 위치의 파일을 수집합니다.

수집 파일 확장자 목록은 다음과 같습니다.

```bash
jpg|jpeg|png|gif|bmp|hwp|doc|docx|xls|xlsx|xlsm|ppt|pptx|pdf|txt|mp3|amr|
m4a|ogg|aac|jpg|jpeg|png|gif|bmp|hwp|doc|docx|xls|xlsx|xlsm|ppt|pptx|pdf|
txt|mp3|amr|m4a|ogg|acc|av|wma|3gpp|eml|lnk|zip|rar|egg|alz|7z|vcf|3gp|
```

### (17) Archive Collected Data: Archive via Library([T1560.002](https://attack.mitre.org/techniques/T1560/002/))

수집한 정보를 ZIP으로 압축합니다. 

### (18) Exfiltration Over C2 Channel

ZIP으로 압축한 파일을 C2채널을 통해 유출합니다.

다음 이미지는 C2서버에 전송된 압축ZIP 파일을 압축 해제 후 확인한 모습입니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled13.png)

## B. 시나리오 시뮬레이션 방법

본 글에서는 개인PC를 타겟으로 정보를 탈취하는 위협을 모사하였기 때문에 여러 대의 타겟 시스템이나 별도의 AD환경 구축이 필요하지 않습니다. 

시뮬레이션을 위해 구축해야 하는 환경은 C2 Server와 Victim System(Windows) 두 개 입니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled14.png)

### (1) C2 Server Setup

Docker 구동이 가능한 시스템에서 다음 명령어를 입력해줍니다.

```bash
git clone https://github.com/hyunjungg/Threat-Hunting.git
cd Threat-Hunting/APT37/Resources
docker run --name apt37_server -d -p 80:80 -v $(pwd)/Compromised_Server/:/var/www/html hyunjungg/apt37:1
```

### (2) Victim System Setup

1909버전 이하의 Windows에서 다음과 같은 설정을 합니다

- Windows Defender OFF
- `C:\Windows\System32\Drivers\etc\host` 파일에 `compromsied.server [C2_server_ip]` 추가

위 두 개의 설정이 끝나면 [rar 파일](https://github.com/hyunjungg/Threat-Hunting/blob/APT37/APT37/Resources/Initial_Execution_Payloads/NorthKorea's_latest_situation.rar)을 다운로드 받고 실행합니다.  rar파일의 압축을 해제 하면(pw : 1234), 악성 Word문서가 생성됩니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled15.png)

악성 Word문서를 더블 클릭 하여 열면 이후 모든 시나리오가 자동으로 실행됩니다.

# 3. 탐지

- 탐지는 **1차 탐지**와 **2차 분석** 으로 나누어져 있습니다. 1차 탐지를 위해서는 ElastAlert를 사용하며, 기본적인 위협을 탐지합니다. 하지만 ElastAlert는 단일 이벤트에 대한 탐지만 가능합니다. 따라서 여러 이벤트를 조합해서 탐지하는 것이 불가능합니다. 이러한 단일 이벤트 탐지의 한계를 2차 분석에서 커버합니다. 2차 분석은 파이썬 Elastic Query Dsl을 사용합니다.
  
    최종적으로 모든 분석이 끝난 후, 위협으로 판단된 프로세스들을 트리 형태로 시각화합니다.
    
- IOC (Indicator of Compromise, 파일명 - 악성 도메인 등 단순 지표) 정보는 탐지에 활용하지 않았습니다.

## A. 탐지 플랫폼

탐지 플랫폼은 아직 미완성 상태입니다.  최종적으로 구축하고자 하는 플랫폼의 파이프라인은 다음과 같습니다. (회색 부분은 미완성으로, 개발 진행 중인부분 입니다.) 

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled16.png)

우선 Target System 에서 Winlogbeat를 통해 Sysmon데이터를 수집합니다. **ElastAlert에서 1차 탐지를 한 후 celery_app에서 2차 탐지를 수행하는 구조로 개발 중입니다.**

2차 탐지까지 진행되면 그래프 DB인 NEO4J에서 프로세스 관계를 시각화하고, 그중 악성 프로세스를 식별하여 화면에 표시함으로써 위협 정보를 가시화하는 것을 최종 목표로 하고 있습니다.

하지만 앞서 언급 드렸듯이 아직 구현이 덜 된 부분이 있기 때문에,  2차 탐지 로직을 Jupyter Notebook을 통한 구현으로 대체하였습니다.ㅎㅎ 

탐지 플랫폼 구축이 완료되는 대로 본 글을 수정할 예정이며, Jupyter Notebook을 통해 임시로 구축한 파이프라인은 다음과 같습니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled17.png)

## B. 1차 탐지

1차 탐지 및 분석을 위해서 ElastAlert를 사용합니다. 

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled18.png)

ElastAlert는 Elastic의 Query Dsl을 활용하기 때문에 탐지 룰 개발이 크게 어렵지 않습니다.

APT37 위협을 탐지하기 위해 개발한 1차 탐지룰의 개수는 총 10개이며, 각 룰은 [여기](https://github.com/hyunjungg/Threat-Hunting/tree/APT37/APT37/Detection/ElastAlert)서 확인하실 수 있습니다. 룰의 신빙성을 위해 룰 개발 시 참고한 문서의 링크를 각 룰 내에 기재해놓았습니다.



- Rule 파일명

Rule의 파일명은 `[TYPE]_[OS]_[ACIVITY]_[LEVEL]` 과 같은 형식으로 구성되어있습니다.

e.g) `proc_creation_win_exploit_cve_2022_30190_HIGH`

맨 마지막의 Level 값은 해당 룰의 위협 정도를 표기한 것이며 **HIGH**, **MEDIUM**, **LOW** 세 가지로 나뉩니다.  ([SigmaHQ](https://github.com/SigmaHQ/sigma)를 참고하여 Level을 표기했습니다.)

LEVEL 값은 추후 프로세스의 위협 정도를 판단하는 데에 사용되며 각각의 score는 10, 2, 1로 정했습니다.

alert 발생 시 alert가 발생한 process 정보를 다음과 같은 파이썬 딕셔너리 구조체에 저장합니다.

```python
{ 
	process_guid : {
										"score" : score,
											"tag" : tag
									} ,
			
							:
							:			 
}
```

이후 계속 alert가 발생할 때마다 Level에 해당하는 score값을 더하여 위협 가중치를 계산하는 식으로 분석시스템을 구성했습니다.



- Rule 내용

전체 룰에 대해 설명하면 내용이 너무 길어질 것 같아 10 개중 2개의 룰에 대해서만 소개합니다.

참고로 아래 룰들을 이해하기 위해선 elastic query dsl에 대한 이해가 조금 필요합니다. 관련 부분은 [이 문서](https://esbook.kimjmin.net/05-search)에 정말 잘 설명이 되어있으니 참고해 주세요!

### (1) Detecting CVE_2022_30190

```yaml
name: proc_creation_win_exploit_cve_2022_30190_HIGH
type: any
es_host: es-01
es_port: 9200
index: winlogbeat-*
filter:
- query:
    bool:
      filter:
      - match_phrase:
          event_id: '1' # process create
      - match_phrase:
          parent_image_path: sdiagnhost.exe
      must_not:
      - bool:
          should:
          - match_phrase:
              image_path: conhost.exe
          - match_phrase:
              image_path: csc.exe
          - match_phrase:
              image_path: TiWorker.exe
          - match_phrase:
              image_path: MoUsoCoreWorker.exe
          - match_phrase:
              image_path: TrustedInstaller.exe
          - match_phrase:
              image_path: RtkAudioService64.exe
          - match_phrase:
              image_path: spoolsv.exe
          - match_phrase:
              image_path: WaaSMedicAgent.exe
          - match_phrase:
              image_path: sc.exe
          - match_phrase:
              image_path: net.exe
          - match_phrase:
              image_path: ipconfig.exe
          - match_phrase:
              image_path: netsh.exe
          minimum_should_match: 1

alert:
- "debug"

## Ref : https://conscia.com/blog/vulnerability-spotlight-how-to-detect-follina-the-windows-msdt-0-day/
```

CVE_2022_30190을 사용하여 공격을 수행하는 경우, sdiagnhost.exe 프로세스에서 악성 페이로드가 실행됩니다.

하지만 sdiagnhost.exe는 Windows 시스템에서 문제 해결을 위해 자주 실행되는 프로세스이기 때문에, sdiagnhost.exe 프로세스가 실행되는 모든 경우를 탐지해버리면 오탐이 빈번히 발생하게 됩니다.

따라서 정상적으로 sdiagnhost.exe가 동작하는 경우 실행되는 자식 프로세스를 화이트리스트로 지정해 줍니다. 

이 룰이 탐지된 경우에는 의심에 여지가 없이, 해당 행위가 발생한 프로세스는 malicious하다고 판단할 수 있으므로 Rule Level을 HIGH로 설정 해 주었습니다.

### (2) Detecting DLL Side Loading

```yaml
name: image_load_side_load_from_non_system_location_HIGH
type: any
es_host: es-01
es_port: 9200
index: winlogbeat-*
filter:
- query:
    bool:
      filter:
      - match_phrase:
          event_id: '7' # DLL Load
      - bool:
          should:
          - match_phrase:
              image_loaded: shfolder.dll
          - match_phrase:
              image_loaded: userenv.dll
          - match_phrase:
              image_loaded: atl.dll
          - match_phrase:
              image_loaded: audioses.dll
          - match_phrase:
              image_loaded: authz.dll
          - match_phrase:
              image_loaded: avrt.dll
          - match_phrase:
              image_loaded: authfwcfg.dll
          - match_phrase:
              image_loaded: adsldpc.dll
          - match_phrase:
              image_loaded: bcd.dll
          - match_phrase:
              image_loaded: cldapi.dll
          - match_phrase:
              image_loaded: clipc.dll
          - match_phrase:
              image_loaded: colouri.dll
          - match_phrase:
              image_loaded: connect.dll
          - match_phrase:
              image_loaded: cscobj.dll
          - match_phrase:
              image_loaded: d2d1.dll
          minimum_should_match: 1
      must_not:
      - bool:
          should:
          - match_phrase:
              image_loaded: C:\Program Files\WindowsApps\DellInc.DellSupportAssistforPCs
          - match_phrase:
              image_loaded: C:\Program Files\Common Files\microsoft shared\ClickToRun\AppVPolicy.dll
          - match_phrase:
              image_loaded: C:\Windows\System32\
          - match_phrase:
              image_loaded: C:\Windows\SysWOW64\
          - match_phrase:
              image_loaded: C:\Windows\WinSxS\
          - match_phrase:
              image_loaded: C:\Windows\SoftwareDistribution\
          - match_phrase:
              image_loaded: C:\Windows\SystemTemp\
          minimum_should_match: 1

alert:
- "debug"

## Ref : https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_side_load_from_non_system_location.yml
```

Windows 기본 프로그램에서 DLL Hijacking에 자주 사용되는 dll목록들을 blacklist에 넣어줍니다. 이때 dll이 `must_not` 부분에 명시된 경로들이 아닌 경우에만 탐지합니다.

해당 경로들은 Windows에서 보호되고 있는 디렉토리이기 때문에 접근이 제한됩니다. 따라서 보통  위 디렉토리에 있는 프로세스를 다른 폴더로 복사한 후 DLL Hijacking 기법을 수행합니다.

이 룰도 이전 룰과 마찬가지로 탐지가 되었을 시 해당 행위가 발생한 프로세스는 malicious하다고 판단할 수 있으므로 Rule Level을 HIGH로 설정해 주었습니다.

## C. 2차 분석/탐지

앞서 말씀드렸듯이 ElastAlert는 단일 이벤트에 대한 탐지만 가능합니다.

따라서 파이썬 ES DSL 라이브러리를 사용하여 직접 다른 이벤트와의 연관 분석이 추가로 이루어져야 합니다. 

이 파트에서는 이러한 추가 탐지와, 추가 탐지 후 malicious한 프로세스들을 식별하여 프로세스 트리 형태로 시각화합니다.  결과는 Jupyter Notebook을 통해 보여줍니다.

모든 코드는 [여기](https://github.com/hyunjungg/Threat-Hunting/blob/APT37/APT37/Detection/Analyzer/Analyzer.ipynb)에 작성해 놓았으며, 이해를 위해서는 해당 문서를 함께 보는 것이 좋을 것 같습니다. 문서를 기준으로 순서대로 각 Step을 설명하겠습니다. 

### (1) Set up Analyzing

분석을 위해 필요한 설정과 함수들을 구성합니다. ES 인덱스 정보나 시뮬레이션 시간 범위 등을 정의하는 부분입니다.

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled19.png)

### (2) ****Analyze processes with rules****

ElastAlert에 의해 1차 탐지된 프로세스들을 대상으로 2차 분석합니다. 단일 이벤트로는 분석이 불가능한 룰들을 작성합니다. 예를 들어 하나의 프로세스에서 네트워크 이벤트와 파일 이벤트의 수가 특정 threshold를 넘은 경우, 정보 탈취 행위로 간주할 수 있습니다.

하지만 파일 업로드 프로그램 같은 경우에는 이런 룰이 오탐이 될 수 있기 때문에, Level을 HIGH가 아닌 MEDIUM이나 LOW로 설정해 주어야 합니다.

### (3) ****Find processes related to malicious process****

ElastAlert에 의해 탐지된 모든 프로세스들을 대상으로 프로세스 트리를 생성합니다.  트리의 시작은 탐지된 프로세스가 아닌, 프로세스 트리의 ROOT가 될 수 있는 프로세스( e.g explorer.exe , svchost.exe)입니다. ROOT가 될 수 있는 프로세스들까지 트리에 포함 시킨 이유는 침입 경로 확인을 위한 분석에 도움이 되기 때문입니다.

Windows System에는 정말 많은 svchost.exe 가 존재하기 때문에, ROOT 프로세스를 좀 더 명확히 구분하기 위한 Root_Handler 함수를 구현했습니다.

이 함수에는 svchost.exe의 command line을 확인하여, svchost.exe 역할을 분류합니다.

svchost.exe의 commandline에 대해서 좀 더 자세히 설명하겠습니다.

- svchost.exe
  
    ![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled20.png)
    
    svchost.exe는 위 이미지에 나와 있는 것 처럼 다양한 플래그들과 함께 실행됩니다. 플래그 값의 의미는 다음과 같습니다.
    
    - `K` : `KEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` 키에 요청이 보내짐.  해당 레지스트리 value는 관련 서비스 정보를 string type으로 포함하고 있음. 해당 value 값들을 토대로 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\[Service Name]` 에서 관련 서비스를 찾아서 로드 시킴.
    - `S` : 위의 K옵션으로 지정된 서비스 그룹에서 하나의 서비스만 지정.
    - `P` : 정책 관련.

위 설명에 따라, 제가 작성한 분석로직에서 parent process의 commandline이 `svchost.exe -k netsvcs -p -s Schedule` 의 경우 Windows 스케줄러에 의해 실행된 프로세스로 정의했습니다.

### (4) Visualize

마지막 시각화 단계로 프로세스 정보를 트리화해서 보여줍니다. score 점수에 따라 프로세스 노드 색상을 구분했습니다.  노드의 색상은 기본적으로 Red 계열인데, score점수가 높을 수록 색의 명도가 높아집니다.

ROOT 프로세스 노드들은 노란색으로 별도 표시했습니다.

공격자들이 WMI, DLL Load, Windows Scheduler 와 같은 기능을 활용하여 공격을 수행하게 되면 위협 행위를 수행하는 프로세스들의 트리가 끊어지는 경우가 많기 때문에, 분석에 용이하도록 ROOT프로세스들을 별도로 표기합니다.

이렇게 시각화 과정까지 거치면 시스템에서 실행된 프로세스 중, 위협과 관련 있는 프로세스를 식별할 수 있습니다.

시각화 결과는 다음과 같습니다. 

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled21.png)

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled22.png)

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled23.png)

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled24.png)

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled25.png)

아무래도 제가 프론트엔드를 배워서 직접 출력해 줘야 할 것 같습니다. ㅎㅎ 라이브러리로는 한계가 있네요.

사실 제 목표는 아래처럼 모든 위협 정보를 직관적으로 이해할 수 있게 표현해 주는 것입니다...

![Untitled](Threat_Hunting_Detecting_APT37_TTPs\Untitled26.png)

갈 길이 너무 많이 남았지만… 열심히 공부해서 목표를 이루겠습니다 ..

오늘은 APT37 행위를 모사하여 직접 시뮬레이션을 하고, 위협을 탐지하는 방법에 대해서 포스팅을 해봤습니다. 내용이 너무 방대하다 보니 제대로 설명되지 않은 부분이 있는 것 같네여..  부족한 부분에 대해 피드백해 주시면 감사하겠습니다 ㅎㅎ

# 4. 참고

- [KISA TTPS Report](https://www.notion.so/TTPs-9-f04ce99784874947978bd2947738ac92)
- [Kaspersky](https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/)
- [Anlab](https://asec.ahnlab.com/ko/47622/)
- [SigmaHQ](https://github.dev/SigmaHQ/sigma/tree/master/rules/windows/network_connection)