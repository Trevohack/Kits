1. Compile it using:

   ```gcc -fPIC -shared hide.c -o hide.so -ldl```



2. load into /etc/ld.so.preload

3. see the magic your file which you mention in macros got hidden for confirming do ls

POC:

<img width="716" height="237" alt="image" src="https://github.com/user-attachments/assets/330bec3e-fc92-4aa2-8f04-33fe43faefd2" />


See my test.txt hided before by using this :).
