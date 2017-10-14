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
