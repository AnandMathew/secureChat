#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cerrno>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <wait.h>
#include <unistd.h>
#include <cstddef>
using namespace std;

string hex_encoded (const unsigned char * s, unsigned int len) {
    const char * const hex_digits = "0123456789abcdef";

    string encoded;
    encoded.reserve (2*len);
    for (unsigned int i = 0; i < len; i++)
    {
        encoded += hex_digits[s[i]/16];
        encoded += hex_digits[s[i]&0xF];
    }

    return encoded;
}

string hex_encoded_Anand (char* s)
{
    
    std::stringstream ss;
    for(int i=0; s[i] != '\0'; ++i)
        ss << std::hex << (int)s[i];
    std::string encoded = ss.str();

    return encoded;
}

string hex_decoded (string str) {

    string decoded;
    decoded.resize(2*str.size());
    
    for (int i = 0; i < str.size(); i+=2)
    {
        //check for 1st char
        str[i] = tolower(str[i]);
        //for 1st char
        if(isdigit(str[i])){
            str[i] = str[i] - '0';
        }
        if(isalpha(str[i])){
            str[i] = str[i] - 'a' + 10;
        }
        
        //check for 2nd char
        str[i+1] = tolower(str[i+1]);
        if(isdigit(str[i+1])){
            str[i+1] = str[i+1] - '0';
        }
        if(isalpha(str[i+1])){
            str[i+1] = str[i+1] - 'a' + 10;
        }
        
        const int code = 16 * str[i] + str[i+1];
        decoded = decoded + static_cast<char>(code);
    }
    return decoded;
}

string hex_decoded_2(string hex) {
    int len = hex.length();
    std::string newString;
    for(int i=0; i< len; i+=2)
    {
        string byte = hex.substr(i,2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        newString.push_back(chr);
    }
    return newString;
}





int main (int argc, char * arg[])
{
    // generate challenge

    char Ybuffer[128];
    FILE *fp = fopen("/dev/urandom", "r");
    fread(Ybuffer, 1, 16, fp);
    Ybuffer[strlen(Ybuffer)-(strlen(Ybuffer)-16)]='\0';
    fclose(fp);
    // std::cout << "R: "<< R << "\n";

    const unsigned char * para = (const unsigned char *)Ybuffer;
    int lo = strlen((char*) para);

    cout << "charcter buffer: " << Ybuffer << endl;

    cout << "length of charcter buffer: " << lo << endl;


    
    std::cout << "RH: "<< hex_encoded(para, lo) << "\n";

    std::cout << "RDecoded: "<< hex_decoded_2(hex_encoded(para, lo)) << "\n";
    std::cout << "RDecoded: "<< hex_decoded_2(hex_encoded(para, lo)).length() << "\n";

    
    

    return 0;
}



   