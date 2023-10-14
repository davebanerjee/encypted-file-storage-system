#ifndef CSTORE_OBJECT_H
#define CSTORE_OBJECT_H

#include "../crypto_lib/sha256.h"
#include "../crypto_lib/aes.h"
#include "../part1_hmac/hmac_lib.h"
#include "../part2_aes/aes_lib.h"
#include "cstore_args.h"
#include <stdio.h>
#include <vector>
#include <string.h>
#include <iostream>
#include <fstream>

#define MAGIC "./cstore"

class CStoreObject
{
    private:
        std::string                         archive_name;
        std::string                         password;
        char                                signature[SHA256_BLOCK_SIZE]; // confirm whether char or BYTE
        unsigned int                        num_files;
        std::vector<std::string>            file_names; // automatically deallocates memory
        std::vector<unsigned long long int> file_sizes; // we use unsigned long long int because it stores 8 bytes.
        std::vector<std::string>            encrypted_file_datas; // the first 16 bytes include the IV

    public:
        void                                print_error_and_quit(std::string err);
        std::string                         get_archive_name();
        std::string                         get_password();
        char *                              get_signature();
        unsigned int                        get_num_files();
        std::vector<std::string>            get_file_names();
        std::vector<unsigned long long int> get_file_sizes();
        std::vector<std::string>            get_encrypted_file_datas();
        void                                calculate_new_signature(char * new_signature);
        void                                encrypt_and_add_file_to_CStoreObject(std::string file);

        CStoreObject(CStoreArgs args, bool archive_exists);
};


#endif
