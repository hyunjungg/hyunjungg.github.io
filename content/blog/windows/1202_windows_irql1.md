---
title: 'Windows IRQL 1'
date: 2021-12-02 00:58:13
category: 'windows'
draft: false
---

# Dispatch Level에서 Dispatcher 호출하기!



## 1. 개요

안녕하세여!!!!!!!

오늘은 IRQL을 좀 더 자세히 이해하기 위해서 간단한 테스트를 해보려고 합니다!!!!!!!!!!!!!!!!!!
IRQL을 공부하다 보면 인터럽트 마스킹이라는 개념을 접하게 되는데요,

이를 눈으로 직접 확인해보겠습니다.!



동작 방식 확인을 위해서 IRQL Dispatch level에서 동작하는 코드를 작성하고, 해당 코드 내부에서 dispatcher 를 호출 해서 시스템이 크래시 나는 과정을 한번 보려고 합니다.~

좀 더 자세히 말하면,  `SetTimer()` 로 DPC 루틴을 등록하여 실행시킨 후, 해당 DPC루틴 내부에서 `KeDelayExecutionThread()` 를 통해 퀀텀시간을 반납하여 dispatcher 를 호출해 볼 예정입니다. ㅎㅎ 



블루스크린이 발생한다는 사실은 알고 있지만
드라이버 개발을 할 일이 없기 했고..  드라이버를 활용하여 만들어 보고 싶은것도 없었기 때문에, 제 눈으로 직접 확인해 볼 수 있는 기회가 없었던 것 같아여 .... ㅎ_ㅎ T^T



그럼 먼저 이해를 위해 알아야 할 개념들을 설명하겠습니다.!



## 2. 개념

### 1. 윈도우 스케줄링 

윈도우의 스케줄링 코드는 커널에 구현돼 있지만, 별도의 루틴으로 존재하는 것이 아니라 커널내부에 산재해 있습니다! 이런 작업을 수행하는 루틴들을 합쳐 **Kernel Dispatcher** 라고 부릅니다 .

Kernel Dispatcher가 호출 되는 상황의 예시를 몇 가지 들어보겠습니다.!

* 스레드의 퀀텀시간이 종료되는 경우

  이 경우, Dispatcher 가 바로 호출 되는 것이 아니라 아래와 같은 과정을 거치게 됩니다!

  ```
  DIRQL 레벨에서 Timer Interrupt Handler 호출 
  
  -> 해당 핸들러에서 Timer DPC Routine 등록 
  
  -> Dispatcher 호출
  ```

* 스레드가 자발적으로 퀀텀시간을 반납하는 경우

  이 경우, 커널 Dispatcher 가 바로 호출되고 대기 중이었던 다른 Thread 가 호출 되게 됩니다.

  이때 만약 대기 중인 스레드가 존재하지 않는다면, Dispatcher는 Idle Thread 를 호출합니다.

  ( 참고로, Idle Thread는 CPU 개수만큼 존재합니다. !)



이렇게 Kernel Dispatcher에서 스케줄링 관련 이벤트가 일어나게 되는데요~  이렇게 스레드의 문맥이 전환이 되면 **Context Switching** 이 일어나게 됩니다.!

Context Switching 이란 현재 실행 중인 스레드와 관련된 휘발성 프로세서 정보를 저장한 후 새로운 스레드의 상태 값을 가져와 새로운 스레드의 실행을 시작하는 과정을 말합니다!

휘발성 프로세서 정보가 무엇일까여 ?! ㅎㅎ

일반적으로 Context Switching  에서는 다음의 자료들을 저장합니다!

* Instruction Pointer
* Kernel Stack Pointer
* Process의 Page Table Directory Pointer 

참고로 마지막에 쓴 프로세스의 페이지 테이블 디렉토리 포인터는 CPU의 CR3 레지스터 값에 저장되게 됩니다.!

커널은 이러한 정보들을 커널모드 스택에 넣고, 스택 포인터를 스레드의 KTHREAD 블록에 저장합니다.

--> 해당 부분에 대해 다음시간에 Windbg로 분석해보는 시간을 가지려구 합니다 ^^ 재밌겟져 



### 2. IRQL

IRQL은 인터럽트의 우선순위로, 코어의 개수만큼 존재합니다!!

x64환경 기준으로 

```
0 - PASSIVE_LEVEL

1 - APC_LEVEL

2 - DISPATCH_LEVEL

3 ~ 11 - DIRQLs

12 ~ 15 - HIGH_LEVEL
```

이렇게 구성되어 있습니다.

<u>높은 IRQL의 코드는 낮은 IRQL에서 실행하는 코드를 선점할 수 있습니다!</u> 이를 **Interrupt Masking** 이라고 합니다.

참고로 IRQL 은 스레드 우선순위와는 다릅니다.. 실제로 스레드 우선순위는 IRQL이 2보다 작을 때에만 의미를 가집니다~

그럼 중요한 IRQL 들 중 0번과 2번에 대해 설명 해 보겠습니다!

* PASSIVE ( IRQL 0 )

  보통의 스레드 코드가 흐르는 레벨입니다. 특별히 아무것도 발생하지 않고 일반적인 소프트웨어나 드라이버 코드들이 실행되는 레벨 입니다! ( 설명이 이상하네요 .. )

* DISPATCH_LEVEL ( IRQL 2 )

  **1번 윈도우 스케줄링 개념 설명** 에서 언급했던 Kernel Dispatcher 가 동작하는 IRQL 입니다! 스레드가 현재 IRQL을 2 이상으로 상승 시키게 되면, 스레드는 기본적으로 <u>무한 퀀텀</u> 을 갖게 되고, 다른 스레드에 의해 선점될 수 없습니다!!!!!!!!!!

  그럼 여기서 굉장히 중요한 이야기를 해보겠습니다.  

  방금 전에 제가 위에서 Interrupt Masking 에대한 개념을 설명했고, Kernel Dispatcher 는 **IRQL DISPATCH_LEVEL** 에서 동작한다고 했습니다.!!

  그럼 IRQL이 **DISPATCH_LEVEL** 이상일 때, 페이징이 발생하면 어떻게 될까요 ???...
  이런 경우에 시스템이 크래시 되게 됩니다.! ( 블루스크린이 발생합니다 .. )

  실제로 페이징이 발생한다는 것은 Page Fault 가 처리된다는 것인데요! Page Fault가 처리되는 과정에서 Context Switching 이 일어나기 때문에 Dispatcher 가 호출되게 됩니다.! 

  따라서 IRQL 2 또는 그 이상의 레벨에서 실행하는 코드는 NonPaged Memory 만을 접근해야합니다.



### 3. DPC

Deferred Procedure Call 이라 불리는 DPC 루틴은 **IRQL Dispatch_LEVEL**에서 호출 됩니다.

주로 DPC는 인터럽트 후처리를 위해 존재합니다.

IRQL 3 이상의 값을 가지는 루틴에서 .. 스레드를 오랫동안 가지고 있게되면, 우선 순위가 낮은 루틴들은 아무것도 못하게 되잖아여?

따라서 현재 실행에 꼭 필요한 기능만을 수행하고, 다른 기능들은 DPC 담아 DPC 큐에 등록합니다!

그럼 나중에 IRQL DISPATCH_LEVEL 에서 등록된 DPC 루틴들이 실행되게 되는 거에요!!

정확한 순서는 아래와 같습니다.

![222AFD385883A84E31](img\222AFD385883A84E31.jpg)

```
1. 인터럽트 발생
2. 발생한 인터럽트가 IRQL 이 높을 경우 현 상태를 저장하고 IDT를 참조하여 ISR 실행
3. ISR이 동작하면서 CPU의 IRQL을 올림
4. 덜 중요한 작업들은 Dpc 큐에 넣음
5. ISR 이 종료되면 IRQL 이 DPC 레벨로 낮아짐
6. DPC의 인터럽트들을 실행하고 큐의 모든 객체를 실행한 다음 원래 Thread로 복귀 
```





## 3. 실습 

실습을 위해 유저모드 Application과 레거시 드라이버. 이렇게 두 가지를 작성하였으며, 글에서는 코드 일부만 첨부하였습니다.!

글 초반에서 언급했듯이, 실습해볼 내용은 다음과 같습니다.!

1. UserMode Application에서 제가 작성한 드라이버코드로 Read 요청을 보내 ReadDispatch를 호출 시킵니다.
2. 드라이버의 ReadDispatch에서 `KeSetTimer()` 함수로 timer 10초 세팅 + DPC 루틴 등록 후 실행 시킵니다.!
3. 10초 뒤 호출된 DPC 루틴에서 `KeDelayExecutionThread()` 함수를 사용하여 자발적으로 퀀텀 시간을 반납해줍니다.

3번 까지 실행되고 나면..  블루스크린을 볼 수 있을 텐데요 ㅎㅎ

코드는 아래와 같습니다.

* irql_test.sys

```c++
NTSTATUS ReadDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp) {
	
	PDEVICE_EXTENSION pDE;
	pDE = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	pIrp->IoStatus.Status = STATUS_SUCCESS;

	pDE->pPendingIrp = pIrp;
	IoMarkIrpPending(pIrp); // 비동기 IO 완료를 위해 필요

	LARGE_INTEGER Result;
	Result.QuadPart = -1 * 10 * 10000000; // 10초 타이머 세팅 
	KeSetTimer(&pDE->Timer, Result, &pDE->Dpc);

	return STATUS_PENDING;  // 비동기 IO 완료를 위해 필요

}
```

```c++
VOID DpcRoutine(
	struct _KDPC* Dpc,
	PVOID  DeferredContext,
	PVOID  SystemArgument1,
	PVOID  SystemArgument2
)
{
	PDEVICE_EXTENSION pDE = DeferredContext;
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);


    LARGE_INTEGER Result;
    Result.QuadPart = -1 * 10 * 10000000; //10초 설정 

    KeDelayExecutionThread(KernelMode, FALSE, &Result);
	
	IoCompleteRequest(pDE->pPendingIrp, IO_NO_INCREMENT); 
}
```

* application.c

```c++
	handle = CreateFileW(L"\\??\\IRQL", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	bRet = ReadFile(handle, NULL, NULL, NULL, NULL);
```



다음으로 실제 가상환경에서 해당 드라이버 코드를 실행 시킨 후 WinDBG로 확인하는 과정을 하나씩 하나씩 살펴보겠습니당.

우선 드라이버를 가상환경에 올려줍시다!

![image-20211129021308727](img\image-20211129021308727.png)

이제 해당 환경에 Windbg를 붙이고 제 드라이버의 ReadDispatch 루틴과 DpcRoutine에 break point를 걸어줍니다!

![image-20211129022043078](img\image-20211129022043078.png)

이렇게 세팅한 후 가상환경에서 application을 실행시키면, ReadDispatch에 bp 가 걸리게 됩니다.!

![image-20211129021910788](img\image-20211129021910788.png)

이 때의  IRQL 레벨과 실행중인 스레드를 확인해 볼까요 ?

![image-20211129022227084](img\image-20211129022227084.png)

참고로 prcb 구조체는 windows가 cpu를 추상화한 구조체 입니다.! 
prcb 값을 확인해 보면 현재 IRQL LEVEL 은 PASSIVE(0) 이고, 현재 Thread는 `ffffcb82292d3080` 인 것을 확인할 수 있는데요! 해당 스레드에 대한 정보를 확인해보겠습니다.!

![image-20211129022634188](img\image-20211129022634188.png)

당연히 제가 실행시킨 application의 컨택스트 이구여! ( 해당 application 이름은 ConsolApplication1.exe 가 맞습니다. )

현재 Running 상태인 것을 확인해 볼 수 있습니다.



아까 위에 첨부한 코드에서 알 수 있듯이, ReadDispatch 내부에서 10초 타이머를 세팅 시켰는데요~ 실제로 디버거를 Go 시키게 되면 10초 뒤에 DpcRoutine의 break point가 잡히게 됩니다.

![image-20211129023101129](img\image-20211129023101129.png)

오오 위에 사진에서 보시다시피 DpcRoutine에서 멈췄습니다.
이 때의 IRQL LEVEL은 몇일까요!?  당연히 Dispatch Level 이겠죠?

![image-20211129023437141](img\image-20211129023437141.png)

그럼 이때의 스레드는 누구일까요 ??

![image-20211129023843207](img\image-20211129023843207.png)

ConsolApplication 스레드가 아닌 다른 스레드입니다! 여기서는 System 스레드 였네요 ㅎㅎ

이제  `kd > u fffff805556a1030 L20` 커맨드로 어셈블리를 확인한 후 `KeDelayExecutionThread()`에 bp를 걸어 보겠습니다! ( 굳이 bp를 거는 이유는 .. 블루스크린이 뜨기 전의 마지막 드라이버코드이기 때문입니다.. )

![image-20211129024314132](img\image-20211129024314132.png)

![image-20211129024346385](img\image-20211129024346385.png)

그럼 이제 go 해보겟습니다!!

![image-20211130212319831](img\image-20211130212319831.png)

헉.. 







오늘은 이렇게 IRQL 인터럽트 마스킹 개념에 대해 알아 보았습니다!!!

커널을 공부한다는 건 정말 재밌는 일 같아요 ㅎㅎ! 다음에는 컨텍스트 스위칭이 일어나는 과정을 분석 해보거나, 다양한 버그체크 덤프들을 분석하는 글을 포스팅 해보려고 합니다.!

윈도우즈 커널에 대한 복잡한 내용을 쉽게 설명 해주시는 이봉석 대표님께 너무 감사드립니다. ㅎㅎ



## 참고

* https://rockball.tistory.com/7
* 하제소프트 이봉석님 유튜브 🤍 - https://www.youtube.com/channel/UC7Ek4hbKRdWT1idaZLz-F_Q

* [Windows Internals, Part 1]
