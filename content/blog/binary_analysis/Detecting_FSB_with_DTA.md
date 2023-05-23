---
title: 'Detecting Format String Bugs with Libdft64'
date: 2023-03-05 16:58:13
category: 'binary_analysis'
draft: false
---

본 글에서는 DTA라이브러리인 LIBDFT64를 사용하는 방법을 간단한 예제와 함께 설명합니다. 



### [TOC]

- [1. LIBDFT64?](#1-libdft64-)
- [2. DTA?](#2-dta-)
  * [A. DTA란 무엇인가?](#a-dta-------)
  * [B. 퍼징과 다른 점?](#b----------)
  * [C. DTA의 세 가지 요소](#c-dta---------)
  * [D. Taint Policy](#d-taint-policy)
  * [E. 한계..](#e---)
- [3. LIBDFT64 설치 및 사용 방법](#3-libdft64-----------)
  * [A. 설치](#a---)
  * [B. LIBDFT64 내부 구조](#b-libdft64------)
  * [C. LIBDFT64 API](#c-libdft64-api)
  * [D. 빌드 방법](#d------)
- [4. LIBDFT64로 Format String Bug 탐지](#4-libdft64--format-string-bug---)
  * [A. Format String Bug 탐지 방안](#a-format-string-bug------)
  * [B. 테스트 대상 프로그램 빌드 시 유의 사항](#b-----------------------)
  * [C. DTA 툴 작성](#c-dta-----)
  * [D. 결과](#d---)
- [5. 참고](#5---)




# 1. LIBDFT64?


![[https://github.com/AngoraFuzzer/libdft64](https://github.com/AngoraFuzzer/libdft64)](Detecting_FSB_with_DTA\Untitled.png)

기존에 많이 알려져 있는 [libdft](https://www.cs.columbia.edu/~vpk/research/libdft/)는 32비트 바이너리만 지원하는데, 리서치 도중 64비트 호환이 가능하게 [libdft64](https://github.com/AngoraFuzzer/libdft64) 프로젝트를 진행해 주신 분이 계셔서 사용해 보았습니다.!

Libdft는 인텔의 Pin을 기반으로 작성된 DTA 라이브러리 입니다. 현재 알려진 DTA 라이브러리 중 가장 많이 사용되고 있습니다.

MMX나 SSE와 같은 확장 명령어는 지원하고 있지 않으므로, 분석 대상 프로그램 컴파일 시 해당 명령어들이 포함되지 않게 해주셔야 합니다.! gcc 의 경우 `-mno-{mmx, sse, sse2, sse3}` 를 추가해주시면 됩니당.

# 2. DTA?


## A. DTA란 무엇인가?

DTA (Dynamic Taint Analysis)는 프로그램에서 사용자 입력 값으로 인해 어떤 레지스터와 메모리 영역이 제어 가능한지 확인하는 기법입니다. 

런타임 정보를 사용하므로 STA(정적 오염 분석) 보다 결과의 신뢰도가 높습니다. 
또한 정적 분석은 컴파일 시점에 오염 분석 기능을 삽입하기 때문에 소스코드가 제공되는 경우에만 가능합니다. 이에 반해 DTA는 빌드 된 바이너리에 분석 기능 삽입이 가능합니다.  ([Binary Ninja 등의 툴을 활용하면  정적 분석도 바이너리 레벨에서 taint analyze가 가능하긴 합니다!](https://www.zerodayinitiative.com/blog/2022/2/14/static-taint-analysis-using-binary-ninja-a-case-study-of-mysql-cluster-vulnerabilities))

하지만 DTA를 수행하면 계측 대상 프로그램이 성능상 엄청난 부하를 감수할 수밖에 없습니다. 아주 최적화된 방법을 사용하더라도 10배 혹은 그 이상의 성능 저하가 발생합니다..ㅠㅠ

## B. 퍼징과 다른 점?

DTA도 퍼징처럼 소프트웨어 취약점을 이용해서 나타날 수 있는 소프트웨어의 오류를 찾아내고 대처할 수 있는 분석 방법 중 하나입니다.

퍼징은 버그를 탐지할 때 주로 외부에 드러나는 현상을 중심으로 관찰합니다. 특히 프로그램의 Crashing, Hanging 현상을 활용합니다. 

이처럼 일반적인 퍼징이 주로 관찰 가능한 버그만 찾을 수 있는 상황에 사용하는 것이라면, DTA는 정보 유출 혹은 Logical Bugs 등 충돌이 발생하지 않는 버그에 사용됩니다.

## C. DTA의 세 가지 요소

큰 시각에서 봤을 때 오염 분석은 세 가지 요소를 정의하는 과정으로 출발합니다. 먼저 **Taint Source**를 설정하고, **Taint Sink**를 정의한 후 **Taint Propagation**를 추적합니다. 

(실제 DTA툴 개발 시, 개발자는 앞 두 가지만 정의하면 됩니다. **Taint Progatation**은 통상적으로 라이브러리가 지원해 줍니다.)

![Untitled](Detecting_FSB_with_DTA\Untitled1.png)

용어 설명 전, 이해를 돕기 위해 아주 쉬운 예시 상황을 설정하겠습니다.

서버와 클라이언트가 send와 recv함수를 사용해 통신합니다. 이때 사용자가 악의적으로 버퍼오버플로우를 일으켜 exec_buf 값을 수정하여 원하는 명령어를 실행할 수 있습니다.

위와 같은 상황을 탐지하기 위해서는 각 요소를 어떻게 설정해야 할까여??

- Taint Source

추적하고자 선택한 특정 데이터의 프로그램 내 위치입니다. 위 상황에서는 **recv**함수가 해당됩니다.

따라서 분석 툴 개발 시 recv 시스템 콜 콜백함수를 사용하면 됩니다.

- Taint Sink

오염된 데이터(Taint Source로 설정한 데이터)로부터 영향을 받았는지 여부를 확인하고자 하는 프로그램 내의 위치입니다.

위 상황에서는 **execve**함수가 됩니다.

- Taint Propagation

프로그램 내에서 오염된 데이터가 어떻게 흘러가는지 추적하려면 해당 데이터를 처리하는 모든 명령어에 대해 계측을 수행해야 합니다. mov, xor, shl 와 같은 모~든 명령어를 계측하여 일부 바이트라도 영향을 미치면 전부 오염시킵니다. 

이 부분은 Taint Policy의 영향을 받습니다. Taint Policy에 대해서는 바로 다음 파트에서 설명하겠습니당.

## D. Taint Policy

DTA 시스템에서 오염이 전파되는 기준에 대한 정의입니다.  또한 중첩된 오염이 발생한 경우 색깔을 어떻게 merge해 표기할지를 정의합니다. 

몇 가지 X64 명령어를 예시로 설명합니다.

참고로 아래 설명에서 T는 Taint(오염된) 메모리를 의미합니다.

- MOV

![Untitled](Detecting_FSB_with_DTA\Untitled2.png)

mov 같은 단순한 연상의 경우 전파되는 규칙이 명확합니다.

결과값은 단순히 T의 복사본이기 때문에 A역시 오염된 메모리 T의 오염 정보를 그대로 전수받습니다.

결과적으로 이 경우에 Taint merge operation은 `:=` 입니다.(그냥 단순 할당)

- XOR

![Untitled](Detecting_FSB_with_DTA\Untitled3.png)

피연산자가 자기 자신과 동일한 값으로 연산을 수행하는 특수한 xor 연산 상황을 예시로 들겠습니다.

이 경우 항상 결과는 0이 됩니다.

따라서 공격자가 아무리 T 값을 조작하려고 해도 결과값에 대해서 아무런 변화를 줄 수가 없게 되겠쬬?

결과적으로 이 경우의 Taint merge operation은 `Ø` 공집합입니다.

- SHL

![Untitled](Detecting_FSB_with_DTA\Untitled4.png)

변수 T값만큼 A값을 시프트하는 상황입니다. 이러한 경우 T가 한 바이트만 오염되어 있어도 A의 모든 바이트에 영향을 미칠 수 있습니다.

결과적으로 A의 모든 부분에 오염이 전파됩니다.

이 경우 오염 정책의 Taint merge operation은 `:=` 가 됩니다.

## E. 한계..

```python
var = 0;
while(taint--) var++; # taint는 오염된 변수를 의미합니다.
```

코드를 보면 공격자가 taint 변수를 통해 var 값을 변조하는 것을 확인할 수 있습니다. 

gcc로 빌드 후 해당 부분의 명령어를 확인해 보면 아래와 같습니다. 

![Untitled](Detecting_FSB_with_DTA\Untitled5.png)

두 변수 간의 묵시적인 데이터 흐름이 발생하지 않는 것이 확인됩니다.

결국 DTA는 taint 변수 값이 오염된 상황이지만 var 값은 오염되지 않은 것으로 판단하고 이 결과 과소 오염으로 진단하게 됩니다.

# 3. LIBDFT64 설치 및 사용 방법

## A. 설치

ubuntu 20.04 기준 정상 동작했으며, wsl환경을 사용했습니다.

설치 스크립트는 다음과 같습니다.

```bash
#!/bin/bash
git clone https://github.com/AngoraFuzzer/libdft64.git

cd libdft64

./install_pin.sh

export PIN_ROOT=[pintools_path]

make
```

## B. LIBDFT64 내부 구조

![Untitled](Detecting_FSB_with_DTA\Untitled6.png)

- Tagmap: DTA 시스템을 위해 마련되는 가상 메모리 공간입니다. 즉, 메모리 공간의 오염 정보 상태를 기록하는 곳입니다. 
(DTA 에서는 이런 공간을 SHADOW MEMORY라고 부르지만, LIBDFT에서는 TAGMAP 이라는 이름을 사용합니다.)
- Vcpu: CPU 레지스터들의 오염 상태를 관리하는 공간입니다. 메모리 공간뿐 아니라 레지스터도 오염 대상이 될 수 있습니다.
- Tracker: 오염 추적 엔진입니다. `libdft_core.c`에 구현되어 있습니다.

## C. LIBDFT64 API

주요 사용되는 API를  설명합니다.

- tagmap_setb() : 특정 메모리 바이트를 오염된 것으로 표시합니다.
- tagmap_getb() : 특정 메모리 바이트의 오염 여부를 확인합니다.
- syscall_set _pre() 시스템 콜 발생에 대한 사전 콜백을 등록합니다.
- syscall_set _post() : 시스템 콜 발생에 대한 사후 콜백을 등록합니다.
- <u>syscall_desc</u> : 시스템 콜 콜백들을 저장하기 위한 배열입니다.
- ins_set _pre/post() : 명령어에 대한 사전/사후 콜백을 등록합니다.
- <u>ins_desc</u> : 명령어 콜백들을 저장하기 위한 배열입니다.

참고로 밑줄 친 두 개의 배열은 `extern`으로 선언해 주어야 합니다. 

## D. 빌드 방법

1. 분석 대상 프로그램 
   
    dta tool로 분석하고자 하는 프로그램을 `libdft64/tools/obj-intel64` 디렉토리 안에 위치시킵니다.
    
2. dta tool 빌드
   
    개발한 dta tool파일은 `libdft64/tools`폴더에 위치해야 합니다.
    
    `libdft64/tools/makefile.rules` 파일의 31번째 행의 TOOL_ROOTS 변수에 dta tool 파일 이름을 넣습니다. 
    
    이후 `libdft64/` 로 이동해서 make 명령어를 입력합니다.
    
3. 분석 수행
   
    `libdft64/tools/makefile.rules` 의 마지막 행에 다음 makefile rule을 추가합니다.
    
    ```bash
    [name]: $(OBJDIR)/[dta_tool]$(PINTOOL_SUFFIX) ${OBJDIR}/[analysis_target]
         $(PIN) -t $< -- $(OBJDIR)[analysis_target]
    ```
    
    이후 `libdft64/tools/` 경로에서 `make [name]` 을 해주시면, 툴이 분석 대상 프로그램 계측을 시작합니다.
    

# 4. LIBDFT64로 Format String Bug 탐지

## A. Format String Bug 탐지 방안

FSB 탐지 방법은 되게 직관적이고 간단합니다. 

FSB는 사용자가 포맷스트링을 입력할 수 있을 때 발생합니다. 

아래는 본 글에서 dta 툴을 사용한 분석에 사용될 프로그램 코드입니다.

```c
// gcc -o fsb fsb.c -no-pie -fcf-protection=none
#include <stdio.h>

int key = 0;

int main(void){
	
	char buf[0x20] = {0,};
	read(0, buf, 0x20);
	
	printf(buf);

	if(key){
		printf("FSB\n");
	}	

	return 0;
}
```

위 프로그램 내에서의 fsb를 탐지하기 위해 아래와 같이 설계해 줍니다.

- Taint Source : read()
- Taint Sink : printf()

read 함수로 입력되는 값을 오염시키고, 그 값이 printf()함수의 **“첫 번째 인자”** 로 사용되었을 때 FSB가 발생한다고 가정했습니다.(linux x64비트니까 printf()함수의 RDI값을 확인하면 되겠져)

추가적으로 콜백 등록 관련 고려해야 할 부분이 있습니다.

Taint Source인 read()는 시스템 콜에 콜백을 등록해 주면 됩니다.

하지만 LIBDFT를 사용해서 라이브러리 함수를 직접적으로 후킹 할 수 없습니다. 왜냐하면 이 함수는 시스템 콜이 아니기 때문입니다. **대신 명령어 콜백은 사용할 수 있으므로, printf함수의 PLT를 CALL하는 경우를 탐지해 줍니다.**

> * fsb가 일어나는 함수는 sprintf, fprintf 등 다양하지만 위 테스트 코드에 한정해 dta 툴을 작성했습니다. 
> * 'printf() 함수로 바로 이동 하는 상황' 혹은 'read 외 다른 함수로 입력을 받는 상황' 등은 고려하지 않습니다.

## B. 테스트 대상 프로그램 빌드 시 유의 사항

테스트 대상 프로그램을 GCC로 빌드 할 시 꼭 `fcf-protection=none` 옵션을 추가해 주세요!

상기 언급한 대로, DTA 툴 내에서 테스트 대상 프로그램 printf()의 PLT주소를 알아야 합니다.

PLT 주소를 알아내기 위해 DTA 툴에서 분석 대상 ELF의 섹션 정보를 파싱하는데 

`fcf-protection`이 활성화되어 있으면, 빌드 후 바이너리 내에서 `.plt` 섹션을 사용하지 않고 `.plt.sec` 섹션을 사용합니다.

`.plt.sec` 섹션의 코드는 다음과 같은 `endbr64` 명령어로 시작합니다. 

![Untitled](Detecting_FSB_with_DTA\Untitled7.png)

안타깝게도 pin tools의 elf 파싱 로직이 저 부분을 해석하지 못합니다.. 

`fcf-protection` 보안 기법에 대한 설명은 추후 추가하겠습니다. 

## C. DTA 툴 작성

전체 코드는 [여기](https://github.com/hyunjungg/libdft64/blob/master/tools/detect_fsb.cpp)서 확인하실 수 있습니다.

- 초기화 및 콜백 등록

```c
int main(int argc, char **argv){
 
  PIN_InitSymbols();
	
	:
	:  일부 생략
	:

  IMG_AddInstrumentFunction(image_load, 0); // PLT PARSING
  syscall_set_post(&syscall_desc[__NR_read], post_read_hook); // set read callback
  ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR], dta_instrument_call); // set ins callback
	
  /* start Pin */
  PIN_StartProgram();
}
```

- PLT 파싱

```c
static void 
image_load(IMG img, VOID *v){
    if(IMG_IsMainExecutable(img)){

      for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)){

        if(SEC_Name(sec) == ".plt"){
          for(RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)){

            if(RTN_Name(rtn) == "printf@plt"){
                plt_printf = RTN_Address(rtn);
                break;
            }
          }
          break;
        }
      }
:
    }
```

- READ 콜백 함수

```c
static void
post_read_hook(THREADID tid, syscall_ctx_t *ctx){
  
  // only receive input data from STDIN(0)
  if(ctx->arg[SYSCALL_ARG0] != STDIN_FILENO) return ;

  // set the tag marking
  tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, 0x01);
  fprintf(stderr, "[INFO] tainting bytes %p ~ %p (tainted byte : %lu)\n", 
          (void *)ctx->arg[SYSCALL_ARG1],
          (void *)(ctx->arg[SYSCALL_ARG1] + (size_t)ctx->ret),
          (size_t)ctx->ret - 1 );
  
}
```

- CALL 명령어 콜백 함수

```c
dta_instrument_call(INS ins){
 
  if(!INS_IsCall(ins)) return;

  INS_InsertCall(ins,
      IPOINT_BEFORE,
      (AFUNPTR)check_string_taint,
      IARG_CONTEXT ,  
      IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
      IARG_END);

}
```

- 분석 함수

```c
static void
check_string_taint(CONTEXT *ctxt, ADDRINT ip, ADDRINT target){
  
  if(target != plt_printf) return;

  ADDRINT rdiValue = PIN_GetContextReg(ctxt, REG_RDI);
  char buffer[1024] = {0,};

  PIN_SafeCopy(buffer, (VOID*)rdiValue, sizeof(buffer));
  
  for(ADDRINT addr = rdiValue; addr <= end; addr++){
    tag = tagmap_getb(addr);
    if(tag != 0){
      fprintf(stderr, "\n\n\n[WARNING] !!! ADDRESS %p IS TAINTED (tag=0x%02x), ABORTING !!!!!\n\n\n",
            (void *)addr,
            (unsigned int)tag);
      exit(1);
    }
  }
  
}
```

## D. 결과

최종 실행 시, 다음과 같이 정상 동작하는 것을 확인할 수 있습니다.

![Untitled](Detecting_FSB_with_DTA\Untitled8.png)

# 5. 참고 


* https://github.com/AngoraFuzzer/libdft64

* https://terrorgum.com/tfox/books/practicalbinaryanalysis.pdf
