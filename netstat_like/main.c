#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "util.h"

int main(int argc, char** argv) {
    char* l_opt_arg;
    char* const short_options = "tu";
    int c;
    int tcp_only = 0;
    int udp_only = 0;
    struct option opts[] = {
        {"tcp", 0, NULL, 't'},
        {"udp", 0, NULL, 'u'}
    };

    while( ( c = getopt_long(argc, argv, short_options, opts, NULL) ) != -1 ) {
        switch(c) {
            case 't':
                tcp_only = 1;
                break;
            case 'u':
                udp_only = 1;
                break;
            default:
                printf("[usage] ./hw1 [-t|--tcp] [-u|--udp] [filter-string]\n");
        }        
    }
   
    argc -= optind;
	argv += optind;
    
    char* filter_str;
    if ( argc > 0 ) {
        if ( strlen(argv[0]) > 0 ) {
            filter_str = malloc(sizeof(argv[0]));
            strcpy(filter_str, argv[0]);
        }
    }

    if ( tcp_only ) {
        printf("List of TCP connections:\n");
        printf("Proto\tLocal Address\t\t\tForeign Address\t\t\tPID/Program name and arguments\n");
        readTCP4();
        readTCP6();
    }
    else if ( udp_only ) {
        printf("List of UDP connections:\n");
        printf("Proto\tLocal Address\t\t\tForeign Address\t\t\tPID/Program name and arguments\n");
        readUDP4();
        readUDP6();
    }
    else {
        printf("List of TCP connections:\n");
        printf("Proto\tLocal Address\t\t\tForeign Address\t\t\tPID/Program name and arguments\n");
        readTCP4();
        readTCP6();
        printf("\n");
        printf("List of UDP connections:\n");
        printf("Proto\tLocal Address\t\t\tForeign Address\t\t\tPID/Program name and arguments\n");
        readUDP4();
        readUDP6();
    }

    return 0;
}
