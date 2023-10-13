#include "cstore_args.h"

void show_usage(std::string name)
{
    std::cerr << "Usage: " << name << " <function> [-p password] archivename <files>\n"
              << "<function> can be: list, add, extract.\n"
              << "cstore list archivename\n"
              << "cstore add [-p password] archivename file\n"
              << "cstore extract [-p password] archivename file\n"
              << "Options:\n"
              << "\t-h, --help\t\t Show this help message.\n"
              << "\t-p <PASSWORD>\t\t Specify password (plaintext) in console. If not supplied, user will be prompted."
              << "\n\tNote: file names must not exceed 20 characters; further there can be more than one file"
              << std::endl; 
}

void error_and_quit(std::string err) 
{
        std::cerr << err << std::endl;
        exit(1);
}

/**
 * @brief Construct a new User Args:: User Args object
 * 
 * @param argc - program argc for parsing
 * @param argv - program argv for parsing
 */
CStoreArgs::CStoreArgs(int argc, char ** argv)
{
    std::string arg1;
    std::string arg2;
    action = "";
    valid = false;
    if (argc >=3 )
    {
        valid = true;
        arg1 = argv[1];
        if (arg1 == "add" || 
                arg1 == "extract") {
            action = arg1;
        } else if (arg1 == "list") {
            if (argc == 3)
            {
                action = arg1;
                archive_name = argv[2];
                valid = true;
            } else
            {
                valid = false;
            }
            
        } else {
            valid = false;
        }

        if ( valid &&
                action != "list" && 
                action != ""
                )
        {
            if ( argc >=4 )
            {
                unsigned int argc_offset = 0;
                arg2 = argv[2];
                
                if (
                    arg2 == "-p" && 
                    argc >= 6 // otherwise, support edge 
                                // case where archivename == "-p"
                    ) {
                    password = argv[3];
                    argc_offset = 2;
                }
                else
                {
                    char * temp_password = getpass("\tPlease enter a password to use: ");
                    password = temp_password;
                    free(temp_password);
                }
                if (password.length() < 1 ) {
                    error_and_quit("An empty password is not allowed.");
                }
                archive_name = argv[2+argc_offset];
                for (    int index = 3+argc_offset; 
                        index < argc; 
                        index ++
                    )
                {
                    files.push_back(argv[index]);
                    if (files.back().length() > MAX_FILENAME_LENGTH) {
                        valid = false;
                    }
                }
            } else {
                valid = false;
            }
        }
    }
    if (!valid) {
        show_usage(argv[0]);
        exit(1);
    }
}

std::string CStoreArgs::get_action()
{
    return action;
}
std::string CStoreArgs::get_password()
{
    return password;
} 
std::string CStoreArgs::get_archive_name()
{
    return archive_name;
}
std::vector<std::string> CStoreArgs::get_files()
{
    return files;
}