# BumbleCrypt
A Bumblebee-inspired Crypter

## Background

The BumbleCrypt is inspired by Bumblebee's crypter, in Bumblebee's case the main Bumblebee DLL is been loaded in the memory and executed in the following way:
- Decrypts and writes the payload in the Heap
- Hooks three NtApi's - NtOpenFile, NtCreateSection and NtMapViewOfSection
- Calls LoadLibraryW("gdiplus.dll") which triggers the inline hooks as the above three API's are been used by LoadLibrary() to load any library.
- The inline hooks and LoadLibrary itself then loads the main Bumblebee DLL in place of "gdiplus.dll"
- At last, the control is been transferred to the exported function "SetPath" of the main Bumblebee DLL
    
## Working of BumbleCrypt

While analyzing BumbleBee's crypter I realized that the decrypted DLL could be loaded with just one inline hook on "NtMapViewOfSection" instead of three inline hooks used in the Bumblebee's Crypter.
As a result "BumbleCrypt" was developed.

**The BumbleCrypt**:
- The BumbleCrypt first loads an encrypted resource from the .rsrc section and then decrypts the final DLL payload: encrypted res -> Base64 decode -> Rc4 Decrypt -> xor decrypt
- The Crypter leverages the Heap to store the decrypted DLL payload just like the Bumblebee's crypter
- Once the final payload is decrypted, the BumbleCrypt hooks the NtApi "NtMapViewOfSection" which maps is used to map a view of the section into the virtual address space.
- Then the BumbleCrypt calls the LoadLibraryW("msimg32.dll"). Now let's understand how the inline hook is been triggered:

    - The LoadLibraryW() first calls NtOpenFile to retrieve the handle of the module passed as an argument
    - Then it creates a section object with the module's handle using NtCreateSection
    - Now once the section is been created, the LoadLibrary calls the NtMapViewOfSection in order to maps the view of a section the memory
    - **Here** our hook on NtMapViewOfSection is been triggered where the proxy function performs the following actions:
        - First unhooks the NtMapViewOfSection
        - Creates a section of the required size using NtCreateSection()
        - Then maps the view of the created section into the virtual address space using NtMapViewOfSection (unhooked earlier)
        - At last it manually maps the previously decrypted final DLL at the base address of the memory mapped section and then returns NTSTATUS_SUCCESS to the LoadLibraryW and exits from the proxy function 
    - The LoadLibraryW then receives the NTSTATUS_SUCCESS as the response to NtMapViewOfSection and the base address of the memory mapped section where the decrypted malicious DLL lies in the memory.Further the LoadLibrary loads the DLL as per the return values, the outcome is that the msimg32.dll can be seen in the loaded modules but  points to the Decrypted payload. Further the Crypter transfers the control to the decrypted DLL by executing the exported function "CallPath".
    
- Now if we take a look at the screenshot of the BumbleCrypt's loaded modules we can see it contains the "msimg32.dll" but the base address points to the Decrypted Malicious Payload.

**Screenshot**

![s2](https://user-images.githubusercontent.com/60843949/205432516-84a91859-69b6-435b-b99c-ff47b10a9d16.png)

![s3](https://user-images.githubusercontent.com/60843949/205432540-db15d8d5-d0e5-4731-ab3d-a649cf74f90c.png)

## PoC - BumbleCrypter

![s1](https://user-images.githubusercontent.com/60843949/205432713-6d8700a9-9a76-4827-8f5f-b9b699af9e10.png)


Thankyou so much! Hope you liked it =D
You can contact me on Twitter if you have any feedbacks or comments

Twitter: https://twitter.com/knight0x07


# Note 
For educational purposes only. It is a personal weekend project =)









    
    
           
