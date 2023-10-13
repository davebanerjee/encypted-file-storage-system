#include "cstore_object.h"

void CStoreObject::print_error_and_quit(std::string err) {
        std::cerr << err << std::endl;
        exit(1);
}

void CStoreObject::calculate_new_signature(char * new_signature) {
        char null_char = '\0';

        remove("temp_archive"); // ensure no temp_archive already exists
        FILE* temp_archive = fopen("temp_archive", "wb");
        if (temp_archive == NULL) {
                fclose(temp_archive);
                print_error_and_quit("Error: Could not open temp_archive.");
        }

        if (fwrite(&num_files, sizeof(unsigned int), 1, temp_archive) != 1) { // write MAGIC ("./cstore") to beginning of file
                fclose(temp_archive);
                print_error_and_quit("Error: Could not write num_files to temp_archive.");
        }

        for (unsigned int i = 0; i < num_files; i++) {
                const char* curr_file_name = file_names[i].c_str();
                unsigned int curr_file_name_length = file_names[i].size();
                unsigned long long int curr_file_size = file_sizes[i];
                const char* curr_file_data = encrypted_file_datas[i].c_str();
                
                // printf("In calculate_new_signature: filename is %s\n", curr_file_name);
                // printf("In calculate_new_signature: filename size is %d\n", curr_file_name_length);
                
                
                // printf("in calculate, we read currfiledata as: \n");
                // print_hex(curr_file_data, curr_file_size);


                if (fwrite(curr_file_name, sizeof(char), curr_file_name_length, temp_archive) != curr_file_name_length) { // write file name to archive
                        fclose(temp_archive);
                        print_error_and_quit("Error: could not write file_name to archive.");
                }
                for (unsigned int i = 0; i < 20 - curr_file_name_length; i++) { // pads file name with '\0'
                        if (fwrite(&null_char, sizeof(char), 1, temp_archive) != 1) {
                                fclose(temp_archive);
                                print_error_and_quit("Error: could not pad file_name while writing to archive.");
                        }
                }
                if (fwrite(&curr_file_size, sizeof(unsigned long long int), 1, temp_archive) != 1) {
                        fclose(temp_archive);
                        print_error_and_quit("Error: could not write curr_file_size to archive.");
                }

                if (fwrite(curr_file_data, sizeof(char), curr_file_size, temp_archive) != curr_file_size) {
                        fclose(temp_archive);
                        print_error_and_quit("Error: could not write ciphertext to archive.");
                }
        }

        fclose(temp_archive);

        bool success = generate_hmac(
                "temp_archive",
                password.data(),
                password.size(),
                new_signature
                );
        
        if (!success) {
                print_error_and_quit("Error: generate_hmac failed.");
        }
        // remove temp_archive from the directory
        if (remove("temp_archive") != 0) {
                print_error_and_quit("Error: Failed to delete temp_archive.");
        }
} 

/**
 * @brief Construct a new CStoreObject::CStoreObject object by going through
 *  all elements of user_args and assign those data to instance variables 
 * w/in CStoreObject
 */
CStoreObject::CStoreObject(CStoreArgs args, bool archive_exists) {
        if (archive_exists) { // Action cannot be add in this if statement
                // Read directly from archive and populate CStoreObject
                
                archive_name = args.get_archive_name();
                
                const char* archive_name_ptr = archive_name.c_str();
                char magic_num[9];

                FILE* archive = fopen(archive_name_ptr, "rb");
                if (archive == NULL) {
                        print_error_and_quit("Error: Could not open archive.");
                }
                fseek(archive, 0, SEEK_END); // move pointer to EOF to calculate size of archive
                unsigned long archive_size = ftell(archive);
                if (archive_size <= 40) {
                        print_error_and_quit("Error: archive size too small. Missing encrypted files and more.");
                }
                fseek(archive, 0, SEEK_SET); // move pointer back to start
                
                if (fread(magic_num, sizeof(char), 8, archive) != 8) {
                        fclose(archive);
                        print_error_and_quit("Error: Could not read magic number from archive.");
                }
                magic_num[8] = '\0'; // setting null-terminating character so we can strcmp
                if (strcmp(magic_num, MAGIC) != 0) {
                        fclose(archive);
                        print_error_and_quit("Error: Archive begins with invalid magic number.");
                }

                if (fread(signature, sizeof(char), SHA256_BLOCK_SIZE, archive) != SHA256_BLOCK_SIZE) {
                        fclose(archive);
                        print_error_and_quit("Error: Could not read signature from archive.");
                }

                // BEGIN INTEGRITY CHECK

                if (args.get_action() == "extract") {
                        password = args.get_password();
                        char new_signature[SHA256_BLOCK_SIZE] = "0123456789012345678901234567890";
                        
                        // calc archive _size
                        fseek(archive, 0, SEEK_END);
                        long unsigned archive_size = ftell(archive);
                        
                        // move pointer back to 40 bytes
                        fseek(archive, 40, SEEK_SET);
                        char message[archive_size - 40];
                        if (fread(message, sizeof(char), archive_size - 40, archive) != archive_size - 40) {
                                fclose(archive);
                                print_error_and_quit("Error: Could not read message from archive.");
                        }

                        remove("temp_archive"); // ensure no temp_archive already exists
                        FILE* temp_archive = fopen("temp_archive", "wb");
                        if (temp_archive == NULL) {
                                fclose(archive);
                                fclose(temp_archive);
                                print_error_and_quit("Error: Could not open temp_archive.");
                        }

                        if (fwrite(message, sizeof(char), archive_size - 40, temp_archive) != archive_size - 40) {
                                fclose(archive);
                                fclose(temp_archive);
                                print_error_and_quit("Error: Could not write message to temp_archive.");
                        }
                        fclose(temp_archive);

                        bool success = generate_hmac(
                                "temp_archive",
                                password.data(),
                                password.size(),
                                new_signature
                                );
                        
                        if (!success) {
                                print_error_and_quit("Error: generate_hmac failed.");
                        }
                        
                        remove("temp_archive"); // remove temp_archive from the directory

                        for (int i=0; i < SHA256_BLOCK_SIZE; i++) {
                                if (signature[i] != new_signature[i]) {
                                        // printf("signature from archive: ");
                                        // fwrite(signature, sizeof(char), SHA256_BLOCK_SIZE, stdout);
                                        // printf("\nnew_signature: ");
                                        // fwrite(new_signature, sizeof(char), SHA256_BLOCK_SIZE, stdout);
                                        fclose(archive);
                                        print_error_and_quit("Signatures do not match. File has been tampered with.");
                                }
                        }

                        fseek(archive, 40, SEEK_SET); // move pointer back to before integrity check
                }

                // END INTEGRITY CHECK

                if (fread(&num_files, sizeof(unsigned int), 1, archive) != 1) {
                        fclose(archive);
                        print_error_and_quit("Error: Could not read num_files from archive.");
                }

                char curr_file_name[20];
                std::string curr_file_name_string;
                unsigned long long int curr_file_size;
                for (unsigned int i = 0; i < num_files; i++) {
                        if (fread(curr_file_name, sizeof(char), 20, archive) != 20) {
                                fclose(archive);
                                print_error_and_quit("Error: Could not read file_name from archive.");
                        }
                        if (fread(&curr_file_size, sizeof(unsigned long long int), 1, archive) != 1) {
                                fclose(archive);
                                print_error_and_quit("Error: Could not read file_size from archive.");
                        }
                        char curr_file_data[curr_file_size];
                        if (fread(curr_file_data, sizeof(char), curr_file_size, archive) != curr_file_size) {
                                fclose(archive);
                                print_error_and_quit("Error: Could not read file_data from archive.");
                        }
                        // printf("in norm, currfilename: %s", curr_file_name);
                        // printf("in norm, strlen currfilename: %ld\n", strlen(curr_file_name));

                        // append what we've read so far
                        std::string curr_file_name_string(curr_file_name, 20);
                        file_names.push_back(curr_file_name_string);

                        file_sizes.push_back(curr_file_size);

                        std::string curr_file_data_string(curr_file_data, curr_file_size);

                        // printf("while extracting, we read currfiledata string as: \n");
                        // print_hex(curr_file_data_string.c_str(), curr_file_data_string.size());

                        encrypted_file_datas.push_back(curr_file_data_string);
                }
                // OLD METHOD OF INTEGRITY CHECK
                // BEGIN INTEGRITY CHECK
                // if (args.get_action() == "extract") {
                //         // printf("Begin integrity check\n");
                //         password = args.get_password();
                //         char new_signature[SHA256_BLOCK_SIZE] = "0123456789012345678901234567890";
                //         // printf("pre_initialization new_signature: ");
                //         // fwrite(new_signature, sizeof(char), SHA256_BLOCK_SIZE, stdout);
                //         calculate_new_signature(new_signature);
                //         // printf("\noriginal_signature: ");
                //         // fwrite(signature, sizeof(char), SHA256_BLOCK_SIZE, stdout);

                //         // printf("\nintegritycheck_signature: ");
                //         // fwrite(new_signature, sizeof(char), SHA256_BLOCK_SIZE, stdout);
                //         // fflush(stdout);
                //         for (int i=0; i < SHA256_BLOCK_SIZE; i++) {
                //                 if (signature[i] != new_signature[i]) {
                //                         // printf("signature from archive: ");
                //                         // fwrite(signature, sizeof(char), SHA256_BLOCK_SIZE, stdout);
                //                         // printf("\nnew_signature: ");
                //                         // fwrite(new_signature, sizeof(char), SHA256_BLOCK_SIZE, stdout);
                //                         fclose(archive);
                //                         print_error_and_quit("Signatures do not match. File has been tampered with.");
                //                 }
                //         }
                // }        
                // END INTEGRITY CHECK
                fclose(archive);
        } else {
                // action is 'add' and archive does not exist
                archive_name   = args.get_archive_name();
                num_files      = args.get_files().size();
                file_names     = args.get_files();
                password       = args.get_password();
                // char null_char = '\0';
                
                // // temp_archive is the file we use to generate the signature
                // FILE* temp_archive = fopen("temp_archive", "wb");
                // if (temp_archive == NULL) {
                //         print_error_and_quit("Error: Could not open temp_archive.");
                // }
                // if (fwrite(&num_files, sizeof(unsigned int), 1, temp_archive) != 1) {
                //         print_error_and_quit("Error: Could not write num_files to temp_archive.");
                // }

                // iterate through every file

                for (const std::string& str : file_names) {
                        // str is the current file



                        // check if file is empty and if it exists
                        std::ifstream curr_file(str);
                        if (!curr_file.good()) {
                                curr_file.close();
                                print_error_and_quit("Error: A file does not exist.");
                        }
                        if (curr_file.is_open()) {
                                curr_file.seekg(0, std::ios::end);
                                if (curr_file.tellg() == 0) {
                                        curr_file.close();
                                        print_error_and_quit("Error: A file is empty.");
                                }
                        } else {
                                print_error_and_quit("Error: Could not open file.");
                        }
                        curr_file.close();


                        auto encrypted = encrypt_file(str, password);

                        // printf("encrypted after adding. IV then ciphertext.\n");
                        // print_hex(encrypted.IV, AES_BLOCK_SIZE);
                        // print_hex(encrypted.ciphertext.data(), encrypted.ciphertext.size());


                        if (encrypted.ciphertext.size() == 0) {
                                print_error_and_quit("Error: Could not open file while encrypting.");
                        }

                        std::vector<char> data_to_write;
                        unsigned long long int curr_file_size = AES_BLOCK_SIZE + encrypted.ciphertext.size();
                        data_to_write.resize(curr_file_size);
                        memcpy((char *) data_to_write.data(), encrypted.IV, AES_BLOCK_SIZE);
                        memcpy((char *) data_to_write.data()+AES_BLOCK_SIZE, 
                                encrypted.ciphertext.data(), encrypted.ciphertext.size());
                        
                        file_sizes.push_back(AES_BLOCK_SIZE + encrypted.ciphertext.size()); // append file_size to file_sizes
                        std::string encrypted_file_data(data_to_write.begin(), data_to_write.end()); // converts from vector of chars to a string
                        
                        // printf("confirm string version is correct\n");
                        // const char * temp_file_data = encrypted_file_data.c_str(); 
                        // print_hex(temp_file_data, strlen(temp_file_data));


                        encrypted_file_datas.push_back(encrypted_file_data); // appends encrypted file data, including IV
                        
                        // const char* curr_file_name = str.c_str();
                        // unsigned int curr_file_name_length = strlen(curr_file_name);

                        // printf("temp: filename is %s\n", curr_file_name);
                        // printf("temp: filename size is %d\n", curr_file_name_length);

                        // if (fwrite(curr_file_name, sizeof(char), curr_file_name_length, temp_archive) != curr_file_name_length) { // write file name to temp_archive
                        //         print_error_and_quit("Error: could not write fil_name to temp_archive.");
                        // }
                        // for (unsigned int i = 0; i < 20 - curr_file_name_length; i++) { // pads file name with '\0'
                        //         printf("printing a pad 0\n");
                        //         if (fwrite(&null_char, sizeof(char), 1, temp_archive) != 1) {
                        //                 print_error_and_quit("Error: could not pad file_name while writing to temp_archive.");
                        //         }
                        // }
                        // if (fwrite(&curr_file_size, sizeof(unsigned long long int), 1, temp_archive) != 1) {
                        //         print_error_and_quit("Error: could not write curr_file_size to temp_archive.");
                        // }
                        // if (fwrite(&encrypted.IV, sizeof(char), AES_BLOCK_SIZE * sizeof(char), temp_archive) != 16) {
                        //         print_error_and_quit("Error: could not write IV to temp_archive.");
                        // }
                        // if (fwrite(encrypted.ciphertext.data(), sizeof(char), encrypted.ciphertext.size(), 
                        //            temp_archive) != encrypted.ciphertext.size()) {
                        //         print_error_and_quit("Error: could not write ciphertext to temp_archive.");
                        // }

                }
                // char new_signature[SHA256_BLOCK_SIZE] = "0123456789012345678901234567890";
                calculate_new_signature(signature);
                // memcpy(signature, new_signature, SHA256_BLOCK_SIZE);

                // Check size of temp_archive
                // long archive_size = ftell(temp_archive);
                // printf("temp_archive size: %ld bytes\n", archive_size);

                // fclose(temp_archive);
                
                // // Assigns new signature
                // bool success = generate_hmac(
                //         "temp_archive",
                //         password.data(),
                //         password.size(),
                //         signature
                //         );

                // if (!success) {
                //         print_error_and_quit("Error: generate_hmac failed.");
                // }

                // // remove temp_archive from the directory
                // if (remove("temp_archive") != 0) {
                //         print_error_and_quit("Error: Failed to delete temp_archive.");
                // }
        }

}

std::string CStoreObject::get_archive_name() {
        return archive_name;
}

std::string CStoreObject::get_password() {
        return password;
}

char * CStoreObject::get_signature() {
        return signature;
}

unsigned int CStoreObject::get_num_files() {
        return num_files;
}

std::vector<std::string> CStoreObject::get_file_names() {
        return file_names;
}

std::vector<unsigned long long int> CStoreObject::get_file_sizes() {
        return file_sizes;
}

std::vector<std::string> CStoreObject::get_encrypted_file_datas() {
        return encrypted_file_datas;
}

CStoreObject::~CStoreObject()
{
 // deconstructor if you need it;
 // deconstructor is used to free up memory after the object goes out of scope or is explicitly destroyed by a cal to delete
}