#include "aes_lib.h"
#include <fcntl.h>


/**
 * @brief encrypts plaintext using AES CBC using key. 
 * buffer allocated in ciphertext must be freed. 
 * Note the current prototype allocates a buffer locally;
 * 
 * @param plaintext - pointer to plaintext buffer; if this ends in a null byte, add
 * a non-null character to the end and then strip it during decryption (or just always
 * do this for deterministic behavior)
 * @param plaintext_length - length in bytes of plaintext
 * @param IV - IV to use 
 * @param ciphertext - should pass a pointer to a pointer. This pointer 
 * will be updated with a heap-based pointer to the final ciphertext. Must be freed by caller.
 * @param ciphertext_length - pointer to int. updated with final length after padding
 * @param key - pointer to key. size is AES_BLOCK_SIZE
 * @return int - returns -1 on error, 0 otherwise.
 */
int encrypt_cbc(const char * plaintext, uint64_t plaintext_length, 
    const char * IV, char ** ciphertext,
    uint64_t * ciphertext_length, char* key )
{
    *ciphertext_length = plaintext_length + 1;
    //uint64_t padding_length = 0;
    if (*ciphertext_length % AES_BLOCK_SIZE != 0) {
        *ciphertext_length = (plaintext_length/AES_BLOCK_SIZE)*AES_BLOCK_SIZE + AES_BLOCK_SIZE;
        //padding_length = *ciphertext_length - plaintext_length;
    }
    *ciphertext = (char *) malloc(*ciphertext_length); 
    if(*ciphertext == NULL) {
        perror("error");
        return -1;
    }
    memset(*ciphertext, 0, *ciphertext_length);
    
    memcpy(*ciphertext, plaintext, plaintext_length); // encryption should take place here
    

    WORD key_schedule[60];
    BYTE key_bytes[SHA256_BLOCK_SIZE];
    BYTE in[AES_BLOCK_SIZE];
    BYTE out[AES_BLOCK_SIZE];
    BYTE curr_IV[AES_BLOCK_SIZE];
    int blocks = *ciphertext_length / AES_BLOCK_SIZE;
    
    memcpy(key_bytes, key, SHA256_BLOCK_SIZE); // convert key to BYTE data type and store in key_bytes
    aes_key_setup(key_bytes, key_schedule, 256);
    memcpy(curr_IV, IV, AES_BLOCK_SIZE); // store initial IV value to curr_IV
    
    for (int i = 0; i < blocks; i++) {
        memcpy(in, *ciphertext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);

        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            in[j] ^= curr_IV[j]; // XOR with curr_IV
        }

        aes_encrypt(in, out, key_schedule, 256);
        memcpy(curr_IV, out, AES_BLOCK_SIZE); // setting new IV for next round
        memcpy(*ciphertext + i * AES_BLOCK_SIZE, out, AES_BLOCK_SIZE);
    }

    return 0;
}

/**
 * @brief read file from disk
 * note that this may fail on very big files
 * 
 * @param filename - file to be read
 * @return std::vector<char> - on fail, this will be empty
 */
std::vector<char> get_data_from_file(std::string filename)
{
    std::ifstream cur_file;
    std::streampos file_size;
    cur_file.open( filename, std::ios::in | std::ios::binary |std::ios::ate );
    std::vector<char> file_contents;
    if (cur_file.is_open())
    {
        file_size = cur_file.tellg();
        file_contents.resize(file_size);
        cur_file.seekg (0, std::ios::beg);
        cur_file.read( (char *) file_contents.data(), file_size);
        cur_file.close();
    }
        
    return file_contents;
}

/**
 * @brief decrypts ciphertext using key and IV stores result in buffer and updates 
 * plaintext with pointer to buffer. Note that decrypt will remove null byte padding. 
 * assumes plaintext does not end in null bytes. If your plaintext will, add a non-null
 * character before encrypting and then strip it after.
 * 
 * @param ciphertext - pointer to buffer with ciphertext
 * @param ciphertext_length - length of ciphertext. should be a multiple of AES_BLOCKSIZE
 * @param IV - IV used to decrypt first block.
 * @param plaintext - double pointer to plaintext buffer. This should be a pointer to a pointer. Once the ciphertext has been decrypted, the first-depth pointer will be updated with a new heap-based buffer containing plaintext
 * @param plaintext_length length of plaintext. Should be ciphertext_length - padding. 
 * @param key - key used for AES 
 * @return int - 0 on success, -1 on error.
 */
int decrypt_cbc(const char* ciphertext, uint64_t ciphertext_length, 
    const char * IV, char ** plaintext, uint64_t * plaintext_length, 
    char* key)
{
    *plaintext_length = ciphertext_length;
    *plaintext = (char *)  malloc(*plaintext_length);
    if(*plaintext == NULL) {
        perror("error");
        return -1;
    }

    memcpy(*plaintext, ciphertext, *plaintext_length); // decryption should take place here.

    WORD key_schedule[60];
    BYTE key_bytes[SHA256_BLOCK_SIZE];
    BYTE in[AES_BLOCK_SIZE];
    BYTE out[AES_BLOCK_SIZE];
    BYTE out_xor[AES_BLOCK_SIZE];
    BYTE curr_IV[AES_BLOCK_SIZE];
    int blocks = *plaintext_length / AES_BLOCK_SIZE;
    
    memcpy(key_bytes, key, SHA256_BLOCK_SIZE); // convert key to BYTE data type and store in key_bytes
    aes_key_setup(key_bytes, key_schedule, 256);
    memcpy(curr_IV, IV, AES_BLOCK_SIZE); // store initial IV value to curr_IV    

    for (int i = 0; i < blocks; i++) {
        memcpy(in, *plaintext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);

        aes_decrypt(in, out, key_schedule, 256);
        memcpy(*plaintext + i * AES_BLOCK_SIZE, out, AES_BLOCK_SIZE);
        memcpy(out_xor, out, AES_BLOCK_SIZE);

        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            out_xor[j] ^= curr_IV[j]; // XOR with curr_IV
        }
        memcpy(*plaintext + i * AES_BLOCK_SIZE, out_xor, AES_BLOCK_SIZE);
        memcpy(curr_IV, ciphertext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE); // setting new IV for next round
    }

    // remove null byte padding
    char * plaintext_ptr = *plaintext;
    for(uint64_t index = ciphertext_length - 1; 
        index > (ciphertext_length - AES_BLOCK_SIZE); index--) {
            if(plaintext_ptr[index] != '\0') {
                break;
            }

            *plaintext_length = index;
    }
    return 0;
}

encrypted_blob encrypt_file(std::string filename, std::string password)
{
    // BEGIN get IV from /dev/urandom
    char IV[AES_BLOCK_SIZE];
    memset(IV,0,AES_BLOCK_SIZE);

    std::ifstream cur_file;
    cur_file.open("/dev/urandom", std::ios::binary);

    if (!cur_file.is_open()) {
        perror("Failed to open /dev/urandom\n");
    } else {
        cur_file.read(IV, AES_BLOCK_SIZE);
    }
    cur_file.close();
    // END get IV from /dev/urandom
    
    // BEGIN gen key from password
    char key[SHA256_BLOCK_SIZE];
    BYTE key_bytes[SHA256_BLOCK_SIZE];

    int password_length = password.length();
    BYTE password_bytes[password_length];
    std::copy( password.begin(), password.end(), password_bytes ); // convert password to BYTE data type
    
    hash_sha256(password_bytes, key_bytes, password_length); // first hash
    for (int i = 1; i < 10000; i++) { // i starts at 1 because we've already hashed once
        hash_sha256(key_bytes, key_bytes, SHA256_BLOCK_SIZE);
    }
    memcpy(key, key_bytes, SHA256_BLOCK_SIZE);
    // END gen key from password

    std::vector<char> plaintext = get_data_from_file(filename);

    char * ciphertext = NULL;
    uint64_t ciphertext_length = 0;

    plaintext.push_back(PAD_CHAR); // ensure padding doesn't consume a null byte in plaintext

    int encrypt_success = encrypt_cbc(plaintext.data(), plaintext.size(), IV, &ciphertext, 
    &ciphertext_length, key);

    std::vector<char> return_vector;
    if(encrypt_success == 0) {
        return_vector.resize(ciphertext_length);
        memcpy(return_vector.data(), ciphertext, ciphertext_length);
    }
    free(ciphertext);

    encrypted_blob return_value;
    return_value.ciphertext = return_vector;
    memcpy(return_value.IV, IV, AES_BLOCK_SIZE);

    return return_value;
}

std::vector<char> decrypt_file(std::string filename, std::string password)
{
    std::vector<char> return_vector;
    char IV[AES_BLOCK_SIZE];

    // BEGIN gen key from password
    char key[SHA256_BLOCK_SIZE];
    BYTE key_bytes[SHA256_BLOCK_SIZE];

    int password_length = password.length();
    BYTE password_bytes[password_length];
    std::copy( password.begin(), password.end(), password_bytes ); // convert password to BYTE data type
    
    hash_sha256(password_bytes, key_bytes, password_length); // first hash
    for (int i = 1; i < 10000; i++) { // i starts at 1 because we've already hashed once
        hash_sha256(key_bytes, key_bytes, SHA256_BLOCK_SIZE);
    }
    memcpy(key, key_bytes, SHA256_BLOCK_SIZE);
    // END gen key from password


    std::vector<char> ciphertext = get_data_from_file(filename);

    if (ciphertext.size() > 16) {
        memcpy(IV,ciphertext.data(),AES_BLOCK_SIZE);
        char * plaintext = NULL;
        uint64_t plaintext_length = 0;

        char * ciphertext_data = ciphertext.data()+16;
        uint64_t ciphertext_size = ciphertext.size()-16;

        int decrypt_success = decrypt_cbc(ciphertext_data, ciphertext_size, IV, 
            &plaintext, &plaintext_length, key);

        if(decrypt_success == 0) {
            return_vector.resize(plaintext_length -1); // consume padding char
            memcpy(return_vector.data(), plaintext, plaintext_length - 1);
        }
        free(plaintext);
    }
        
    return return_vector;
}
