# **Documentation**

## Archive Structure 

The archive is generated in the same layout as specified in the last two pages of the assignment spec.

## CStoreObject

I designed the CStoreObject to populate variables that contain the archive name, password, signature, number of files, file names, file sizes, and the data of each encrypted file (including IV and ciphertext). If the archive already exists, then when creating the CStoreObject, the archive is read and the variables are populated. If the archive does NOT already exist, then when creating the CStoreObject, the CStoreArgs args is read and the CStoreObject variables are populated.

I created a function calculate_new_signature. This function calculates the signature for an archive by generating the hmac of all the data in the archive starting from byte 40 (this is where num_files begins in the archive structure).


## Algorithm for Add

1. Check if archive already exists 
    - If archive does not exist: 
        1. Create archive file
        2. Add magic number (”./cstore”)
        3. Add num_files
    - If archive DOES exist: 
        1. Error out
2. Loop through files
    1. Add file name
    2. Add file size
    3. Encrypt file data using AES-CBC, which will generate IV and encrypted data
    3. Add file IV and file ciphertext
3. After files have been added, we compute CStore signature by taking HMAC of the archive starting from num_files based on the file structure outlined in the last 2 pages of the spec

## Algorithm for List and Extract

The algorithm is very similar to the algorithm for add. The only difference is that rather than populating our CStoreObject with data from CStoreArgs args, we populate our CStoreObject by reading the pre-existing archive.

## Security of Archive

### File Encryption

An active attacker will not be able to determine the contents of the files since each file is AES-CBC encrypted, and only the receiver can decrypt the file with a pre-shared password. I used AES-CBC so that each file in the archive is encrypted in a different way because of the randomness induced by the IV.

### Integrity Protection

We protect integrity by taking the HMAC of the archive starting from byte 40 (where num_files begin). The generated signature must match the signature stored in the archive. If the signatures are different, then the file has been tampered with. We consider three cases:

1. If the hacker tampers any data after byte 40, then the generated signature will definitely be different than the signature within the archive. The hacker could also tamper with the signature stored within the archive, but they would be unable to find a matching signature without the shared password.
2. If the hacker tampers the first 8 bytes (MAGIC), then we will know that the message has been tampered because we do a direct strcmp to confirm that the first 8 bytes of the archive is the MAGIC number ("./cstore").
3. If the hacker tampers the signature (8-40 byte mark within the archive), then the generated signature of the rest of the file will not match the recently tampered signature.

Thus, our file storage system protects integrity.