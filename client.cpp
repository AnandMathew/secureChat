/********************************************************************
 * Author:  Carlos Moreno
 * Created: 2019-06
 * 
 * Description:
 * 
 *      This is a sample code to connect to a server through TCP.
 *      You are allowed to use this as a sample / starting point 
 *      for the assignment (both problems require a program that 
 *      connects to something).
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
# include <vector>
using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <wait.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <locale>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define MINIMUM_TIME 1
#define TIMEOUT_VALUE 5

int socket_to_server (const char * IP, int port);
string read_packet (int socket);

class connection_closed {};
class socket_error {};

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

string hex_decoded (string hex) {
    int len = hex.length();
    string newStr;
    for(int i=0; i< len; i+=2)
    {
        string byte = hex.substr(i,2);
        char chara = (char) (int)strtol(byte.c_str(), NULL, 16);
        newString.push_back(chara);
    }
    return newStr;
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

int main()
{
    int socket = socket_to_server ("127.0.0.1", 10458);
        // The function expects an IP address, and not a 
        // hostname such as "localhost" or ecelinux1, etc.

    if (socket != -1)
    {
        send (socket, "Anand\n", 7, MSG_NOSIGNAL);
        usleep (100000);
        // send (socket, "fromCanada\n", 11, MSG_NOSIGNAL);

        // cout << "Response to password1: " << read_packet (socket) << endl;
        string packet = read_packet (socket);

        time_t startTime = time(NULL);
        cout << "Packet from Server Before Decoding: " << packet << "\n";
        // const string packetDecoded = hex_decoded(packet);
        // cout << "Packet Decoded: " << packetDecoded << "\n";

        int sep = int (packet.find('%', 0));


        string r = packet.substr(0, sep);
        string pEnc = packet.substr(sep + 1, packet.length() - 2);

        cout << "Aftre splittig, R: " << r << "\n";
        cout << "After splitting, P: " << pEnc << "\n";

        string rDec = hex_decoded(r);
        string pDec = hex_decoded(pEnc);

        // cout << "Aftre splittig and decoding, R: " << rDec << "\n";
        // cout << "After splitting and decoding, P: " << pDec << "\n";

        locale loc;
        
        time_t startHashTime = time(NULL);
        while (time(NULL) < startHashTime + TIMEOUT_VALUE) {
            char Ybuffer[128];
            FILE *fp = fopen("/dev/urandom", "r");
            fread(Ybuffer, 1, 16, fp);
            Ybuffer[strlen(Ybuffer)-(strlen(Ybuffer)-16)]='\0';
            fclose(fp);

            string y(Ybuffer);

            string gen = rDec + y + rDec;
            string genHash = sha256(gen);

            if (genHash.find (pEnc, 0) == 0) {
                
                if (time(NULL) < startTime + MINIMUM_TIME ) {
                    usleep(MINIMUM_TIME * 1000000);
                }
                cout << "Hash Computed: " << genHash <<  endl;
                // cout << "gen:  " << gen << endl;
                // cout << "genlength:  " << gen.length() << endl;

                const unsigned char * y2 = (const unsigned char *)Ybuffer;
                int lo2 = strlen((char*) y2);

                
                const string sendme = r + "%" + hex_encoded(y2, lo2)  + "%" + r + "\n";
                cout << "Computed Chalenge that will be sent to the server: " << sendme << endl;
                usleep (100000);
                send (socket, sendme.c_str(), sendme.length(), MSG_NOSIGNAL);
                break;
            }
            
        }
        
        // cout << "Response to password2: " << read_packet (socket) << endl;
    }

    return 0;
}

int socket_to_server (const char * IP, int port)
{
    struct sockaddr_in address;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr (IP);
    address.sin_port = htons(port);

    int sock = socket (AF_INET, SOCK_STREAM, 0);

    if (connect (sock, (struct sockaddr *) &address, sizeof(address)) == -1)
    {
        return -1;
    }

    return sock;
}


// Defined redundantly in client and server source files --- you may 
// want to refactor it as a common function and use it for both.
string read_packet (int client_socket)
{
    string msg;

    const int size = 8192;
    char buffer[size];

    while (true)
    {
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
    }

    throw connection_closed();
}
