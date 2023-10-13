#include "hmac_lib.h"


/**
 * @brief generates a sha256 hash of some input
 *  note that this version handles all of the input
 *  at once. for large files you may want to chunk
 * 
 * @param input a byte array of data
 * @param output a byte array to store the hash; should be 32 bytes
 * @param in_len the size of the input data
 */
void hash_sha256(const BYTE * input, BYTE * output, int in_len)
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, in_len);
    sha256_final(&ctx, output);
}

/**
 * @brief returns a buffer of a hexidecimal representation of a string
 * 
 * @param byte_arr - byte array to print
 * @param len - length of byte array
 */
char *sprint_hex(const char* byte_arr, uint32_t len)
{
    uint64_t buff_len = len*2+1;
    char * buffer = (char *) malloc(buff_len);

    if(buffer == NULL)
        return buffer;

    memset(buffer, 0, buff_len);

    char *buffer_ptr = buffer;

    for(uint32_t index = 0; index < len; index++) {
        sprintf(buffer_ptr, "%02X", (unsigned char) byte_arr[index]);
        buffer_ptr += 2;
    }
    return buffer;
}

/**
 * @brief print a byte string as its hexidecimal representation
 * 
 * @param byte_arr - byte array to print
 * @param len - length of byte array
 */
void print_hex(const char* byte_arr, int len)
{
    char * buff = sprint_hex(byte_arr,len);
    if (buff != NULL) {
        printf("%s\n", buff);
    }
    free(buff);
}

/**
 * @brief print a byte vector as its hexidecimal representation
 *  provided as a brief demonstration for how to interface
 *  between vectors and C arrays
 * 
 * @param bytes a vector of bytes
 */
void print_vector_as_hex(std::vector<char> bytes)
{
        print_hex(bytes.data(), bytes.size());
}

/**
 * @brief writes a binary file to disk
 * 
 * @param filename name of file to write
 * @param data vector of data to write
 */
void write_data_to_file(std::string filename, std::vector<char> data)
{
        std::ofstream outfile;
        outfile.open(filename,std::ios::binary|std::ios::out);
        outfile.write(data.data(),data.size());
        outfile.close();
}


/**
 * @brief Reads a file and generate a hmac of its contents, given a password
 * 
 * @param filename - name of file to generate hmac
 * @param password - password to use when generating secret
 * @param dest - buffer to store the final hash; should be size of a sha256
 * @return true - successfully completed actions
 * @return false - an error occurred 
 */
bool generate_hmac(const char * filename, const char * password, 
        unsigned int password_length, char * dest)
{
    
    std::vector<BYTE> hmac_data;
    std::ifstream cur_file;
    std::streampos file_size;
    std::streampos file_pos = 0;
    bool success = true;

    cur_file.open( filename, std::ios::in | std::ios::binary |std::ios::ate ); // std::ios::ate positions the file pointer to the end of the file
  
    if (!cur_file.is_open()) {
        success = false;
    } else {
        //https://cplusplus.com/reference/istream/istream/read/
        
        file_size = cur_file.tellg(); // returns current position of file
        // pointer, which is the file size since it's positioned at the end
        cur_file.seekg(0, std::ios::beg); // moves file pointer to beg of file

        BYTE password_ipad[65];
        BYTE password_opad[65];
        // zeros out password_ipad and password_opad
        bzero(password_ipad, 65);
        bzero(password_opad, 65);
        
        // If password is longer than 64 bytes, then we will hash the password and
        // pad it with zeros until its 64 bytes long. If the password is 64 bytes 
        // long or less, then we will just pad it with zeros so the password is 
        // 64 bytes long. Stores the new password in new_password.
        if (password_length > 64) {
            // printf("long password\n");
            BYTE password_hashed[SHA256_SIZE_IN_BYTES];
            BYTE password_bytes[password_length];
            
            // converts password into BYTE type
            memcpy(password_bytes, password, password_length);
            // hashes password_bytes and stores in password_hashed
            
            hash_sha256(password_bytes, password_hashed, password_length);
            
            // copies hashed password into password_ipad and opad
            memcpy(password_ipad, password_hashed, SHA256_SIZE_IN_BYTES);
            memcpy(password_opad, password_hashed, SHA256_SIZE_IN_BYTES);
        } else {
            // copies password into password_ipad and opad
            memcpy(password_ipad, password, password_length);
            memcpy(password_opad, password, password_length);
        }        

        // XORs password_ipad and password_opad with ipad (0x36) and opad (0x5c), respectively
        for (int i = 0; i < 64; i++) {
            password_ipad[i] ^= 0x36;
            password_opad[i] ^= 0x5c;
        }

        SHA256_CTX ctx1;
        BYTE h1_output[SHA256_SIZE_IN_BYTES];
        sha256_init(&ctx1);
	    sha256_update(&ctx1, password_ipad, 64);
        
        char chunk[SHA256_SIZE_IN_BYTES];
        BYTE chunk_bytes[SHA256_SIZE_IN_BYTES];
        while (file_pos < file_size && cur_file) {
            cur_file.read(chunk, SHA256_SIZE_IN_BYTES); // stores chunk of data from file in the 'chunk' array
            memcpy(chunk_bytes, chunk, cur_file.gcount()); // convert chunk to BYTE data type
            sha256_update(&ctx1, chunk_bytes, cur_file.gcount());
            file_pos += cur_file.gcount(); // moves file position based on how many bytes were actually read
        }
        sha256_final(&ctx1, h1_output);
        
        SHA256_CTX ctx2;
        BYTE h2_output[SHA256_SIZE_IN_BYTES];
        sha256_init(&ctx2);
	    sha256_update(&ctx2, password_opad, 64);
        sha256_update(&ctx2, h1_output, SHA256_SIZE_IN_BYTES);
        sha256_final(&ctx2, h2_output);
        memcpy(dest, h2_output, SHA256_SIZE_IN_BYTES);
    }

    return success;
}
