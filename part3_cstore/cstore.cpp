#include "cstore_args.h"
#include "cstore_object.h"
#include <algorithm>


void create_archive(CStoreObject cstore) {
        // printf("in create_archive\n");
        char null_char = '\0';
        const char* archive_name_ptr = cstore.get_archive_name().c_str();
        char* signature = cstore.get_signature();
        unsigned int num_files = cstore.get_num_files();
        std::vector<std::string> file_names = cstore.get_file_names();
        std::vector<unsigned long long int> file_sizes = cstore.get_file_sizes();
        std::vector<std::string> encrypted_file_datas = cstore.get_encrypted_file_datas();

        remove(archive_name_ptr); // remove archive in case it already exists, so we can create a new one
        FILE* archive = fopen(archive_name_ptr, "wb"); // open archive in binary write mode

        if (archive == NULL) {
                cstore.print_error_and_quit("Error: Could not create archive file.");
        }

        if (fwrite(MAGIC, sizeof(char), 8, archive) != 8) { // write MAGIC ("./cstore") to beginning of file
                fclose(archive);
                cstore.print_error_and_quit("Error: Could not write MAGIC (./cstore) to archive.");
        }
        if (fwrite(signature, sizeof(char), SHA256_BLOCK_SIZE, archive) != SHA256_BLOCK_SIZE) {
                fclose(archive);
                cstore.print_error_and_quit("Error: Could not write signature to archive.");
        }
        if (fwrite(&num_files, sizeof(unsigned int), 1, archive) != 1) {
                fclose(archive);
                cstore.print_error_and_quit("Error: Could not write num_files to archive.");
        }

        for (unsigned int i = 0; i < num_files; i++) {
                const char* curr_file_name = file_names[i].c_str();
                unsigned int curr_file_name_length = strlen(curr_file_name);
                unsigned long long int curr_file_size = file_sizes[i];
                const char* curr_file_data = encrypted_file_datas[i].c_str();

                if (fwrite(curr_file_name, sizeof(char), curr_file_name_length, archive) != curr_file_name_length) { // write file name to archive
                        fclose(archive);
                        cstore.print_error_and_quit("Error: could not write file_name to archive.");
                }
                for (unsigned int i = 0; i < 20 - curr_file_name_length; i++) { // pads file name with '\0'
                        if (fwrite(&null_char, sizeof(char), 1, archive) != 1) {
                                fclose(archive);
                                cstore.print_error_and_quit("Error: could not pad file_name while writing to archive.");
                        }
                }
                if (fwrite(&curr_file_size, sizeof(unsigned long long int), 1, archive) != 1) {
                        fclose(archive);
                        cstore.print_error_and_quit("Error: could not write curr_file_size to archive.");
                }
                if (fwrite(curr_file_data, sizeof(char), curr_file_size, archive) != curr_file_size) {
                        fclose(archive);
                        cstore.print_error_and_quit("Error: could not write ciphertext to archive.");
                }
        }

        fclose(archive);
}

int main(int argc, char* argv[])
{
        CStoreArgs args = CStoreArgs(argc,argv);

        // Determines if archive already exists
        bool archive_exists;
        if (access(args.get_archive_name().c_str(), F_OK) != -1) {
                archive_exists = true;
        } else {
                archive_exists = false;
        }
        

        if (args.get_action() == "list") {
                if (archive_exists) {
                        CStoreObject cstore = CStoreObject(args, archive_exists);
                        std::cout << "List of files in the archive:" << std::endl;

                        // print all file names
                        std::vector<std::string> file_names = cstore.get_file_names();
                        std::sort(file_names.begin(), file_names.end());

                        for (const std::string& file_name : file_names) {
                                std::cout << file_name << std::endl;
                        }

                } else {
                        std::cerr << "Archive does not exist." << std::endl;
                        return EXIT_FAILURE;
                }
        } else if (args.get_action() == "add") {
                if (archive_exists) {
                        std::cout << "Are you sure you want to overwrite the existing archive (yes/no)? ";
                        std::string response;
                        std::cin >> response;
                        if (response == "yes" || response == "Yes" || response == "YES" || response == "Y" || response == "y") {

                        } else if (response == "no" || response == "No" || response == "NO" || response == "N" || response == "n") {
                                std::cout << "Please enter different archive name." << std::endl;
                                return EXIT_SUCCESS;
                        } else {
                                std::cout << "Invalid response: please enter 'yes' or 'no'." << std::endl;
                                return EXIT_FAILURE;
                        }
                }
                CStoreObject cstore = CStoreObject(args, archive_exists);
                create_archive(cstore);
                std::cout << "Files succesfully added to archive." << std::endl;
        } else if (args.get_action() == "extract") {
                if (archive_exists == false) {
                        std::cerr << "Archive does not exist." << std::endl;
                        return EXIT_FAILURE;
                } else {
                        CStoreObject cstore = CStoreObject(args, archive_exists);
                        
                        std::vector<std::string> file_names_to_extract = args.get_files();
                        std::vector<std::string> file_names = cstore.get_file_names();

                        // check that the files to extract are in fact in the archive
                        unsigned int idx;
                        std::vector<unsigned int> file_name_idxs;
                        bool found_file;
                        bool curr_file_match;
                        for (const std::string& file_name_to_extract : file_names_to_extract) {
                                found_file = false;
                                idx = -1;
                                for (const std::string& file_name : file_names) {
                                        idx++;
                                        // file name lengths do not match skip to next file name
                                        if (file_name_to_extract.size() != strlen(file_name.c_str())) {
                                                continue;
                                        }
                                        
                                        curr_file_match = true;
                                        for (long unsigned int i = 0; i < file_name_to_extract.size(); i++) {
                                                if (file_name[i] != file_name_to_extract[i]) {
                                                        curr_file_match = false;
                                                        break;
                                                }
                                        }
                                        if (curr_file_match) {
                                                found_file = true;
                                                file_name_idxs.push_back(idx);
                                                break;
                                        }
                                }
                                if (found_file == false) {
                                        cstore.print_error_and_quit("Error: Cannot find file to extract from.");
                                }
                        }


                        // decrypt file data and write to file
                        std::vector<char> decrypted_content;
                        for (unsigned int i = 0; i < file_name_idxs.size(); i++) {
                                std::ofstream temp_file("temp_file");
                                if (temp_file.is_open()) {
                                        
                                        temp_file << cstore.get_encrypted_file_datas()[file_name_idxs[i]];
                                        temp_file.close();


                                        decrypted_content = decrypt_file("temp_file", args.get_password());
                                        remove("temp_file");

                                        if(decrypted_content.size() != 0) {
                                                write_data_to_file(file_names[file_name_idxs[i]], decrypted_content);
                                        } else {
                                                cstore.print_error_and_quit("Error: Could not decrypt file.");
                                        }
                                } else {
                                        cstore.print_error_and_quit("Error: Could not open temp_file.");
                                }

                        }
                        std::cout << "Files extracted successfully." << std::endl;
                }
        } else {
                return EXIT_FAILURE;
        }
        
        return EXIT_SUCCESS;
}