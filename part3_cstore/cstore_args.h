#ifndef CSTORE_ARGS_H
#define CSTORE_ARGS_H

#include <string.h>
#include <argp.h>
#include <vector>
#include <iostream>
#include <string>
#include <unistd.h> // reference: https://www.gnu.org/software/libc/manual/html_node/getpass.html

#define MAX_FILENAME_LENGTH 20

class CStoreArgs 
{
    private:
        std::vector<std::string> files;
        std::string password; 
        std::string archive_name;
        std::string action;
        bool valid;

    public: 
        std::string     get_action();
        std::string     get_password();
        std::string     get_archive_name();
        std::vector<std::string> get_files();


        CStoreArgs(int argc, char ** argv);



};

#endif