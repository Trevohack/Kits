
## File Hiding Proof of Concept (PoC)

This demonstrates how to hide files on a Linux system using LD_PRELOAD.

### 🛠️ Steps to Reproduce

Compile the shared object

```bash
gcc -fPIC -shared hide.c -o hide.so -ldl
``` 

Load into ld.so.preload

```bash
echo "/full/path/to/hide.so" | sudo tee -a /etc/ld.so.preload
``` 

Verify the effect
Run ls in a directory containing the target file you defined in the macros of hide.c.
The file should now be hidden from directory listings.

## 📸 Proof of Concept

Below is a demonstration showing how test.txt was successfully hidden:

<img width="716" height="237" alt="image" src="https://github.com/user-attachments/assets/330bec3e-fc92-4aa2-8f04-33fe43faefd2" />

### ✅ Result

As seen above, test.txt was invisible in the directory listing after loading hide.so via LD_PRELOAD 
