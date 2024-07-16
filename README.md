# FreeThreadHijacking
Perform Thread Hijacking Shellcode Injection without OpenProcess and OpenThread mapping all the free handles in memory

Modify the final condition if you change the shellcode because this shellcode was executing a calculator app, and at the end we check if a calculator it's created, if you don't do this, your shellcode might be execute a lot of times:

![image](https://github.com/user-attachments/assets/23b87786-e2df-46eb-8ad5-1eb0eb061533)
