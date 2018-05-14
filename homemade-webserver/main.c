#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>

#define CONNECT_MAX 500
#define RESP_SIZE 1024

// Global Variable
char *root_dir; // Webserver Root
int listenfd; // file descriptor
int clients[CONNECT_MAX]; // connect client

// Function Definition
void error( const char * ); // Make system default error function usable
void StartWebService( char * ); // Handle Starting Service
void RespondClient( int ); // Handle User Request's Respones

int main( int argc, char *argv[] ) {
    struct sockaddr_in client_addr;
    socklen_t addrlen;
    char opt; // handle parameter

    char port[6]; // Web Service Port
    root_dir = getenv("PWD"); // Get Working Directory Location
    strcpy( port, "50000" ); // Default Port 6666


    int slot = 0; // The slot index for incoming client

    printf( "Welcome to simply web server~\n" );

    while ( ( opt = getopt( argc, argv, ":p:d" ) ) != -1 ) {
        switch(opt)
        {
            case 'd': // case for directory path
                root_dir = (char *)realloc( root_dir, strlen(optarg));
                strcpy( root_dir, optarg );
                break;
            case 'p': // case for port number
                if ( strlen(optarg) < 6 && strlen(optarg) > 0 ) { 
                    strcpy( port, optarg );
                }
                else {
                    fprintf( stderr, "Port number length is illegal\n");
                    exit(1); // Exit with error
                }
                break;
            case '?': // case for unknown
                fprintf( stderr, "Unknown command...\n" );
                exit(1); // Exit with error
            default:
                exit(1); // Exit with error

        }
    }

    printf("Server will run at port no.%s%s%s, root directory located at %s%s%s\n", "\033[91m", port, "\033[0m", "\033[91m", root_dir, "\033[0m");

    // Initialize clients to -1: signifies there is no client connected
    for ( int i = 0 ; i < CONNECT_MAX ; i++ ) 
        clients[i] = -1;

    StartWebService( port );

    // Start Accepting Connections
    while ( 1 ) {
        addrlen = sizeof(client_addr);
        clients[slot] = accept( listenfd, (struct sockaddr *) &client_addr, &addrlen );

        if ( clients[slot] < 0 ) {
            error( "accept() error" );
        }
        else {
            // Create a thread to serve client
            if ( fork() == 0 ) {
                RespondClient(slot);
                exit(0);
            }
        }
        
        // Searching avaliable slot for next client
        while ( clients[slot] != -1 ) slot = ( slot + 1 ) % CONNECT_MAX;
    }

    return 0;
}

void StartWebService( char *port ) {
    struct addrinfo hints, *res, *p;

    // getaddrinfo for host
    memset( &hints, 0, sizeof(hints) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ( getaddrinfo( NULL, port, &hints, &res ) != 0 ) {
        perror( "getaddrinfo() error" );
        exit(1); // exit with error
    } 

    // socket and bind
    for ( p = res ; p != NULL ; p = p->ai_next ) {
        listenfd = socket( p->ai_family, p->ai_socktype, 0 );
        if ( listenfd == -1 ) continue;
        if ( bind(listenfd, p->ai_addr, p->ai_addrlen) == 0 ) break;
    }

    if ( p == NULL ) {
        perror( "socket() or bind() error" );
        exit(1); // exit with error        
    }

    freeaddrinfo(res);

    if ( listen( listenfd, 1000000 ) != 0 ) {
        perror("listen() error");
        exit(1); // Exit with error
    }
}

// Respond Client
void RespondClient( int n ) {
    char mesg[8200], data_to_send[RESP_SIZE], fpath[90000];
    char* reqline[3];
    int rcvd, fd, bytes_read;

    memset( mesg, '\0', 8200 );

    rcvd = recv( clients[n], mesg, 8192, 0 );
    
    if ( rcvd < 0 ) { // receive error
        fprintf( stderr, "recv() error\n" );
    }
    else if ( rcvd == 0 ) { // receive socket close
        fprintf( stderr, "client disconnect unexpectedly\n" );
    }
    else { // Message Received
        printf( "%s", mesg );
        reqline[0] = strtok( mesg, " \t\n" );
        if ( strncmp( reqline[0], "GET\0", 4 ) == 0 ) {
            reqline[1] = strtok( NULL, " \t" );
            reqline[2] = strtok( NULL, " \t\n" );
            
            // Check HTTP Version
            if ( strncmp( reqline[2], "HTTP/1.0", 8 ) != 0 && strncmp( reqline[2], "HTTP/1.1", 8 ) != 0 ) {
                write( clients[n], "HTTP/1.0 400 Bad Request\n", 25 );
            }
            else { 
                if ( strncmp( reqline[1], "/\0", 2 ) == 0 )
                   reqline[1] = "/index.html"; // if no file is specified, return default web page
                
                strcpy( fpath, root_dir );
                strcpy( &fpath[strlen(root_dir)], reqline[1] ); 
                printf( "File: %s\n", fpath );

                if ( ( fd = open( fpath, O_RDONLY ) ) != -1 ) { // File Found
                    send( clients[n], "HTTP/1.0 200 OK\n\n", 17, 0 );
                    while ( ( bytes_read = read( fd, data_to_send, RESP_SIZE ) ) > 0 ) {
                        write( clients[n], data_to_send, bytes_read );
                    } 
                }
                else {
                    write( clients[n], "HTTP/1.0 404 Not Found\n", 23 ); // File Not Found
                }
            }
        }
    }

    // Close socket
    shutdown( clients[n], SHUT_RDWR ); // Send and Recieve operation are disabled
    close( clients[n] );
    clients[n] = -1;

}
