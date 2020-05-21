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
using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <wait.h>
#include <unistd.h>
#include <math.h>

#define N 100000



int socket_to_server (const char * IP, int port);
string read_packet (int socket);

class connection_closed {};
class socket_error {};

static __inline__ uint64_t rdtsc()
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}

struct Letter {
        char c;
        double mean;
        double upper;
        double lower;
};

bool compareTwoLetters(Letter a, Letter b) { 
    return (a.mean > b.mean); 
} 

int main()
{
    int socket = socket_to_server ("127.0.0.1", 10458);
        // The function expects an IP address, and not a 
        // hostname such as "localhost" or ecelinux1, etc.


   
    char storec;
    string rd;

    string alphabet = "abcdefghijklmnopqrstuvwxyz";

    Letter alphabetRecords[26];

    if (socket != -1)
    {
        send (socket, "user2\n", 7, MSG_NOSIGNAL);
        usleep (100000);
        // comparetime = std::numeric_limits<uint64_t>::max();
        uint64_t compareMean = 0;
        int counter = 0;
        bool done = false;

        // Tried to implement some more user functionality, but this was
        // messing up the timing, always giving me a, as teh wanted charcter.

        string prefix;
        cout << "Please enter prefix of password: " << endl;
        // cin >> prefix;
        getline (cin, prefix);



        
        for(char c : alphabet) {

            if (done) {
                break;
            }
           
            cout << "character: " << c << endl;
            uint64_t time = 0;
            uint64_t timesq = 0;
            double mean = 0.0;
            double variance = 0.0;

            uint64_t start;
            uint64_t end;
            uint64_t duration;
            
            
            string cconvs(1,c);
            string cconvsEndl = prefix + cconvs + "\n";
            for (int i = 1; i < N; i++) {

                send (socket, cconvsEndl.c_str() , cconvsEndl.length(), MSG_NOSIGNAL);
                start = rdtsc();
                rd = read_packet(socket);
                end = rdtsc();

                // cout << "start inside: " << start << endl;
                // cout << "end inside: " << end << endl;

                duration = end - start;
                // cout << "Duration inside: " << duration << endl;
                
                if (rd == "ok") {
                    cout << "DONE!!" << endl;
                    done = true;
                    break;
                }
                time = time + duration;
                // cout << "Time inside: " << time << endl;

                mean = double(time/((uint64_t)i));
                // cout << "Mean inside: " << mean << endl;
                
                timesq = timesq + ( ( duration ) * ( duration ) ) ;
                // cout << "Timesq inside: " << timesq << endl;
                if (i != 1) {
                    
                    variance = ( timesq - (i * mean * mean) ) / ( i - 1 );
                    // cout << "Variance inside: " << variance << endl;
                }
                
            }

            
            // cout << "Time: " << time << endl;
            // if (time < comparetime) {
            //     cout << "hayyyy" << endl;
            //     comparetime = time;
            //     storec = c;
            // }
            // mean = double(time/((uint64_t)10000));
            

               cout << "Mean: " << mean << endl;
            //  cout << "Timesq: " << timesq << endl;
            //  cout << "Variance: " << variance << endl;
            //  cout << "standard deviation : " << sqrt(variance) << endl;

             double MOE = 1.96 * ( sqrt(variance) / sqrt( N ) );

             alphabetRecords[counter].c = c;

             alphabetRecords[counter].mean = mean;
             alphabetRecords[counter].upper = mean + MOE;
             alphabetRecords[counter].lower = mean - MOE;

            counter = counter + 1;
            
        }

        if (done) {
            cout << "ok" << endl;
        } else {
            sort(&alphabetRecords[0], &alphabetRecords[26], compareTwoLetters );

            cout << "wanted char: " << alphabetRecords[0].c << endl;

            if (alphabetRecords[0].lower > alphabetRecords[1].upper) {
                cout << "this letter can picked with 95% confidence\n";
            
            }
            else {
                cout << "this letter cannot picked with 95% confidence\n";
            }
        }

        

        // // send (socket, "first\n", 11, MSG_NOSIGNAL);
        // cout << "Response to password1: " << read_packet (socket) << endl;
        // send (socket, "password2\n", 11, MSG_NOSIGNAL);
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
