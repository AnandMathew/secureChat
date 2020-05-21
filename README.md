# secureChat
chat between a client and server; utilizes C++ sockets;

To RUN:  
g++ server.cpp -o server -lssl -lcrypto &&  ./server
g++ client.cpp -o client -lssl -lcrypto && ./client

Protects against DDOs attacks by requiring the client to compute a specific hash within a specified time in order for the client to be validated inorder to allow for further  messages
