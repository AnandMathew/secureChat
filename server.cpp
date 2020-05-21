/********************************************************************
 * Author:  Carlos Moreno
 * Created: 2019-06
 * 
 * Description:
 * 
 *      You may use this file as a sample / starting point for the 
 *      server in both questions.  In particular, you are allowed 
 *      to submit your code containing verbatim fragments from this 
 *      file.
 *
 *      For the most part, although the file is a .c++ file, the 
 *      code is also valid C code  (with some exceptions --- pun 
 *      intended! :-) )
 *
 * Copyright and permissions:
 *      This file is for the exclusive purpose of our ECE-458 
 *      assignment 1, and you are not allowed to use it for any 
 *      other purpose.
 * 
 ********************************************************************/

#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cerrno>
using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <wait.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define P_LENGTH 2
#define MINIMUM_TIME 1
#define TIMEOUT_VALUE 5

class connection_closed {};
class socket_error {};

void listen_connections (int port);
void process_connection (int client_socket);
string read_packet (int client_socket);

string removeSpaces(string str) {
    std::string::iterator end_pos = std::remove(str.begin(), str.end(), ' ');
    str.erase(end_pos, str.end());

    return str;
}

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

string hashe (const string & text, const EVP_MD * evp_md) {
    unsigned char hash[EVP_MAX_MD_SIZE];

    EVP_MD_CTX ctx;
    unsigned int mdlen;

    EVP_DigestInit (&ctx, evp_md);
    EVP_DigestUpdate (&ctx, reinterpret_cast<const unsigned char *>(text.c_str()), text.length());
    EVP_DigestFinal (&ctx, hash, &mdlen);

    return hex_encoded (hash, mdlen);
}

string sha256 (const string & text)
{
    return hashe (text, EVP_sha256());
}

void randomNumber(char* myRandomData) {
    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0)
    {
        // something went wrong
        cout << "something went wrong with opening dev/urandom";
        
    }
    else
    {
        ssize_t result = read(randomData, myRandomData, sizeof myRandomData);
        // myRandomData[strlen(myRandomData)-(strlen(myRandomData)-len)]='\0';
        if (result < 0)
        {
            // something went wrong
            cout << "something went wrong with reading random data into the buffer";
            
        }
    }
    close(randomData);
}

string hex_encoded_Anand (char* s)
{
    
    std::stringstream ss;
    for(int i=0; s[i] != '\0'; ++i)
        ss << std::hex << (int)s[i];
    std::string encoded = ss.str();

    return encoded;
}


string hex_decoded(string hex) {
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
string hex_decoded_2(string str) {

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

int main (int argc, char * arg[])
{
    listen_connections (10458);

    return 0;
}

void listen_connections (int port)
{
    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    socklen_t client_len;

    server_socket = socket (AF_INET, SOCK_STREAM, 0);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons (port);

    if (bind (server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) == -1)
    {
        cout << "Could not bind socket to address:port" << endl;
        throw socket_error();
    }

    listen (server_socket, 5);

    while (true)
    {
        client_len = sizeof(client_address);
        client_socket = accept (server_socket,
                                (struct sockaddr *) &client_address,
                                &client_len);

        pid_t pid = fork();
        if (pid == 0)           // if we're the child process
        {
            close (server_socket);    // only the parent listens for new connections

            if (fork() == 0)    // detach grandchild process -- parent returns immediately
            {
                usleep (10000); // Allow the parent to finish, so that the grandparent
                                // can continue listening for connections ASAP

                process_connection (client_socket);
            }

            return;
        }

        else if (pid > 0)       // parent process; close the socket and continue
        {
            int status = 0;
            waitpid (pid, &status, 0);
            close (client_socket);
        }

        else
        {
            cerr << "ERROR on fork()" << endl;
            return;
        }
    }
}

void process_connection (int client_socket)
{
    try
    {
        const string & username = read_packet (client_socket);
        cout << "client trying to connect... " << username << endl;

        char Rbuffer[128];
        char Pbuffer[128];
        
        FILE *fp = fopen("/dev/urandom", "r");
        
        fread(Rbuffer, 1, 16, fp);
        Rbuffer[strlen(Rbuffer)-(strlen(Rbuffer)-16)]='\0';
        fclose(fp);
        
        FILE *fp2 = fopen("/dev/urandom", "r");
        
        fread(Pbuffer, 1, P_LENGTH, fp2);
        Pbuffer[strlen(Pbuffer)-(strlen(Pbuffer)-P_LENGTH)]='\0';

        fclose(fp2);

        // cout << "RBuffer: " << Rbuffer << "\n"; 
        // cout << "PBuffer: " <<  Pbuffer << "\n";

        const unsigned char * para = (const unsigned char *)Pbuffer;
        int lo = strlen((char*) para);

        const unsigned char * para2 = (const unsigned char *)Rbuffer;
        int lo2 = strlen((char*) para2);

        string rstring = hex_encoded(para2, lo2);
        string pstring = hex_encoded(para, lo);

        const string challenge = rstring + "%"+ pstring + "\n";
        
        cout << "Challenge that will be sent to client: " << challenge;
        send(client_socket, challenge.c_str(), challenge.length(),  MSG_NOSIGNAL);

        time_t startTime = time(NULL);
        while (true)
        {
            const string & password = read_packet (client_socket);
            if (time(NULL) < startTime + MINIMUM_TIME) {
                break;
            }
            if (password == "Timeout Exceeded") {
                cout << "Timeout Exceeded" << endl;
                break;
            }
            string decodedPass = hex_decoded(password);
            cout << "Received computed challenge from client: " << password << endl;
           
            int sep = int (password.find('%'));
            string rReceived= password.substr(0, sep);

            

            string rest = password.substr(sep + 1, password.length() - 2);

            int sep2 = int (rest.find('%'));
            string yReceived = rest.substr(0, sep2);

            string remaining = rest.substr(sep2 + 1, rest.length() - 2);

            if ((rReceived.compare(rstring) != 0) || (remaining.compare(rstring)  != 0)  ) {
                
                cout << "Received computed challenge does not start or end with R\n";
                break;
            }

            string yReceivedDec = hex_decoded(yReceived);
            string rReceivedDec = hex_decoded(rReceived);


            string reconstructed = rReceivedDec + yReceivedDec + rReceivedDec;

            // cout << "reconstructed: " << reconstructed << endl;
            if (reconstructed.length() != 48) {
                cout << "Length of computed challenge is not 48 bytes or 384 bits\n";
                break;
            }
            string genHash = sha256(reconstructed);
            cout << "checking the hash: " << genHash << endl;
            if (genHash.find (pstring, 0) == 0) {
                cout << "Welcome" << "\n";
                break;
            }
        }
        close (client_socket);
        cout << "client socket closed\n";
    }
    catch (connection_closed)
    {
    }
    catch (socket_error)
    {
        cerr << "Socket error" << endl;
    }
}


// Defined redundantly in client and server source files --- you may 
// want to refactor it as a common function and use it for both.
string read_packet (int client_socket)
{
    string msg;
    fd_set readset;
    struct timeval timeout;
    

    const int size = 8192;
    char buffer[size];

    /* Call select() */
    do {
        FD_ZERO(&readset);
        FD_SET(client_socket, &readset);

        timeout.tv_sec = TIMEOUT_VALUE;
        timeout.tv_usec = 0;

        select(client_socket + 1, &readset, NULL, NULL, &timeout);

        if (!(FD_ISSET(client_socket, &readset))) {
            break;
        }

        int bytes_read = recv (client_socket, buffer, sizeof(buffer) - 2, 0);
        // Though extremely unlikely in our setting --- connection from 
        // localhost, transmitting a small packet at a time --- this code 
        // takes care of fragmentation  (one packet arriving could have 
        // just one fragment of the transmitted message)
        if (bytes_read > 0)
        {
            buffer[bytes_read] = '\0';
            buffer[bytes_read + 1] = '\0';

            const char * packet = buffer;
            while (*packet != '\0')
            {
                msg += packet;
                packet += strlen(packet) + 1;

                if (msg.length() > 1 && msg[msg.length() - 1] == '\n')
                {
                    istringstream buf(msg);
                    string msg_token;
                    buf >> msg_token;
                    return msg_token;
                }
            }
        }

        else if (bytes_read == 0)
        {
            close (client_socket);
            throw connection_closed();
        }

        else
        {
            cerr << "Error " << errno << endl;
            throw socket_error();
        }

    } while (true);
    throw connection_closed();
    return "Timeout Exceeded";
}
