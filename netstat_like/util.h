#ifndef __HW1_HEADER__
#define __HW1_HEADER__
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <regex.h>

typedef struct ipv4_struct {
    int serial_num;
    char* local_addr;
    int local_port;
    char* remote_addr;
    int remote_port;
    char connect_stat[2];
    char trans_queue[8];
    char rec_queue[8];
    char timer_act[2];
    char jiff_until_expires[8];
    char unrecovered_timeout[8];
    unsigned long uid;
    unsigned long timeout_number;
    unsigned long inode;
    unsigned long socket_ref_count;
    char loc_socket[16];
    /* 
     Rest of the information are useless in this program,
     so I just ignore it.
    */
} ipv4_struct;

typedef struct ipv6_struct {
    int serial_num;
    char* local_addr;
    int local_port;
    char* remote_addr;
    int remote_port;
    char connect_stat[2];
    char trans_queue[8];
    char rec_queue[8];
    char timer_act[2];
    char jiff_until_expires[8];
    char unrecovered_timeout[8];
    unsigned long uid;
    unsigned long timeout_number;
    unsigned long inode;
    unsigned long socket_ref_count;
    char loc_socket[16];
    /* 
     Rest of the information are useless in this program,
     so I just ignore it.
    */
} ipv6_struct;

typedef struct ipv4_struct_node {
    ipv4_struct* data;
    struct ipv4_struct_node *next ;

} ipv4_node;

typedef struct ipv6_struct_node {
    ipv6_struct* data;
    struct ipv6_struct_node *next;
} ipv6_node;

/*
 * Hex to Dec ( 16->10 )
 */
int convertHexToDec(char* hexIP) {
    int result = 0;
    int base = 1;

    for ( int i = strlen(hexIP) - 1 ; i >= 0 ; i-- ) {
        if ( hexIP[i] >= '0' && hexIP[i] <= '9' ) {
            result += ( hexIP[i] - '0' ) * base ;
        }     
        else if ( hexIP[i] >= 'A' && hexIP[i] <= 'F' ) {
            result += ( hexIP[i] - 'A' + 10 ) * base;
        }
        else if ( hexIP[i] >= 'a' && hexIP[i] <= 'f' ) {
            result += ( hexIP[i] - 'a' + 10 ) * base;
        }


        base *= 16;
    }


    return result;
}

/*
 * B80D01200000000067452301EFCDAB89 -> 2001:0db8:0000:0000:0123:4567:89ab:cdef
 */
char* convertToRegularHex(char* hexIP){
    char* result = malloc(sizeof(hexIP) + 8);
    int index = 0;
    for ( int i = 0 ; i < strlen(hexIP) ; i += 8 ){
        char* word = malloc(8);
        strncpy(word, hexIP+i, 8);

        for ( int j = strlen(word) - 1 ; j >= 0 ; j -= 2 ) {
            result[index++] = word[j-1];
            result[index++] = word[j];
            if ( j == 5 ) 
                result[index++] = ':';
        }  

        result[index++] = ':';
    }

    return result;
}

/*
 * 0100A8C0 -> 192.168.0.1
 */
char* convertHex2DecIPv4(char* hexIP) {
    char* result = malloc(sizeof(hexIP) + 7);
    int index = 0;

    for( int i = strlen(hexIP) - 1 ; i >= 0 ; i = i - 2 ) {
        char* word = malloc(2);
        strncpy(word, hexIP+i, 2);
        char* decIP = atoi(convertHexToDec(word));
        for ( int j = 0 ; j < strlen(decIP) ; j++ ) {
            result[index++] = decIP[j];   
        }
        
        if ( i != 1 ) 
            result[index++] = '.';    
    }

    return result;
}

/*
 * 01BB -> 403
 */ 
int convertHex2DecPort(char* hexPort) {
    char* port = malloc(4*sizeof(char));
    strncpy(port, hexPort, 4);
    return convertHexToDec(port);
}


ipv4_node* parseIPv4(FILE* pFile) {
    ipv4_node* ip_list_header = malloc(sizeof(ipv4_node));
    ipv4_node* ptr = ip_list_header;
    ipv4_struct* ipv4 = malloc(sizeof(ipv4_struct));
    char c;
    /* this is a flag that decide wheather we need to flush the line */ 
    int flushline = 1; 
     /* there is no data in this file are longer than 16,
        but still give a 5 extra space, just for safty */
    char tmp[16 + 5];
    memset(tmp, '\0', sizeof(tmp));
    int index_tmp = 0;
    int index_field = 0;
    while( (c = fgetc(pFile) ) != EOF ) {
        if ( flushline ) {
            if ( c == '\n' ) {
                flushline = 0;
            }

            continue;
        }
        else if ( c == '\n' ) {
            strcpy(ipv4->loc_socket, tmp);
            ptr->data = ipv4;
            ptr->next = malloc(sizeof(ipv4_node));
            ptr = ptr->next;
            ipv4 = malloc(sizeof(ipv4_struct));
            memset(tmp, '\0', sizeof(tmp));
            index_tmp = 0;
            index_field = 0;
        }
        else if ( c == ' ' || c == ':' ) {
            if ( index_tmp != 0 ) {
                if ( index_field == 0 ) {
                    ipv4->serial_num = atoi(tmp);
                }
                else if ( index_field == 1 ) { 
                    char* endptr;
                    struct in_addr *ip = malloc(sizeof(struct in_addr));
                    ipv4->local_addr = malloc(INET_ADDRSTRLEN * sizeof(char));
                    ip->s_addr = strtoul(tmp, &endptr, 16);
                    inet_ntop(AF_INET, ip, ipv4->local_addr, INET_ADDRSTRLEN);
                } 
                else if ( index_field == 2 ) {
                    ipv4->local_port = convertHex2DecPort(tmp);
                }
                else if ( index_field == 3 ) {
                    char* endptr;
                    struct in_addr *ip = malloc(sizeof(struct in_addr));
                    ipv4->remote_addr = malloc(INET_ADDRSTRLEN * sizeof(char));
                    ip->s_addr = strtoul(tmp, &endptr, 16);
                    inet_ntop(AF_INET, ip, ipv4->remote_addr, INET_ADDRSTRLEN);
                }
                else if ( index_field == 4 ) {
                    ipv4->remote_port = convertHex2DecPort(tmp);
                }
                else if ( index_field == 5 ) {
                    strcpy(ipv4->connect_stat, tmp);
                }
                else if ( index_field == 6 ) {
                    strcpy(ipv4->trans_queue, tmp);
                }
                else if ( index_field == 7 ) {
                    strcpy(ipv4->rec_queue, tmp);
                }
                else if ( index_field == 8 ) {
                    strcpy(ipv4->timer_act, tmp);
                }
                else if ( index_field == 9 ) {
                    strcpy(ipv4->jiff_until_expires, tmp);
                }
                else if ( index_field == 10 ) {
                    strcpy(ipv4->unrecovered_timeout, tmp);
                }
                else if ( index_field == 11 ) {
                    char *endptr;
                    ipv4->uid = strtoul(tmp, &endptr, 10);
                }
                else if ( index_field == 12 ) {
                    char *endptr;
                    ipv4->timeout_number = strtoul(tmp, &endptr, 10);
                } 
                else if ( index_field == 13 ) {
                    char *endptr;
                    ipv4->inode = strtoul(tmp, &endptr, 10);
                }
                else if ( index_field == 14 ) {
                    char *endptr;
                    ipv4->socket_ref_count = strtoul(tmp, &endptr, 10);
                }
                else if ( index_field == 15 ) {
                    strcpy(ipv4->loc_socket, tmp);
                    ptr->data = ipv4;
                    ptr->next = malloc(sizeof(ipv4_node));
                    ptr = ptr->next;
                    ipv4 = malloc(sizeof(ipv4_struct));
                    memset(tmp, '\0', sizeof(tmp));
                    index_tmp = 0;
                    index_field = 0;
                    flushline = 1;
                    continue;
                }

                memset(tmp, '\0', sizeof(tmp));
                index_tmp = 0;
                index_field++;
            }
            
        }
        else {
            tmp[index_tmp++] = c;
        }
    }

    return ip_list_header;
}

ipv6_node* parseIPv6(FILE* pFile) {
    ipv6_node* ip_list_header = malloc(sizeof(ipv6_node));
    ipv6_node* ptr = ip_list_header;
    ipv6_struct* ipv6 = malloc(sizeof(ipv6_struct));
    char c;
    /* this is a flag that decide wheather we need to flush the line */ 
    int flushline = 1; 
     /* there is no data in this file are longer than 32,
        but still give a 5 extra space, just for safty */
    char tmp[32 + 5];
    memset(tmp, '\0', sizeof(tmp));
    int index_tmp = 0;
    int index_field = 0;
    while( (c = fgetc(pFile) ) != EOF ) {
        if ( flushline ) {
            if ( c == '\n' ) {
                flushline = 0;
            }

            continue;
        }
        else if ( c == '\n' ) {
            strcpy(ipv6->loc_socket, tmp);
            ptr->data = ipv6;
            ptr->next = malloc(sizeof(ipv6_node));
            ptr = ptr->next;
            ipv6 = malloc(sizeof(ipv6_struct));
            memset(tmp, '\0', sizeof(tmp));
            index_tmp = 0;
            index_field = 0;
        }
        else if ( c == ' ' || c == ':' ) {
            if ( index_tmp != 0 ) {
                if ( index_field == 0 ) {
                    ipv6->serial_num = atoi(tmp);
                }
                else if ( index_field == 1 ) { 
                    char* endptr;
                    struct in6_addr *ip = malloc(sizeof(struct in6_addr));
                    ipv6->local_addr = malloc(INET6_ADDRSTRLEN * sizeof(char));
                    for( int i = 0 ; i < 4 ; i++ ) {
                        char *sub1 = malloc(2 * sizeof(char));
                        char *sub2 = malloc(2 * sizeof(char));
                        char *sub3 = malloc(2 * sizeof(char));
                        char *sub4 = malloc(2 * sizeof(char));
                        sub1[0] = tmp[i * 8];
                        sub1[1] = tmp[i * 8 + 1];
                        sub2[0] = tmp[i * 8 + 2];
                        sub2[1] = tmp[i * 8 + 3];
                        sub3[0] = tmp[i * 8 + 4];
                        sub3[1] = tmp[i * 8 + 5];
                        sub4[0] = tmp[i * 8 + 6];
                        sub4[1] = tmp[i * 8 + 7];
                        ip->s6_addr[i * 4] = strtoul(sub4, &endptr, 16);
                        ip->s6_addr[i * 4 + 1] = strtoul(sub3, &endptr, 16);
                        ip->s6_addr[i * 4 + 2] = strtoul(sub2, &endptr, 16);
                        ip->s6_addr[i * 4 + 3] = strtoul(sub1, &endptr, 16);
                    }
                    inet_ntop(AF_INET6, ip, ipv6->local_addr, INET6_ADDRSTRLEN);
                } 
                else if ( index_field == 2 ) {
                    ipv6->local_port = convertHex2DecPort(tmp);
                }
                else if ( index_field == 3 ) {
                    char* endptr;
                     struct in6_addr *ip = malloc(sizeof(struct in6_addr));
                     ipv6->remote_addr = malloc(INET6_ADDRSTRLEN * sizeof(char));
                     for( int i = 0 ; i < 4 ; i++ ) {
                        char *sub1 = malloc(2 * sizeof(char));
                        char *sub2 = malloc(2 * sizeof(char));
                        char *sub3 = malloc(2 * sizeof(char));
                        char *sub4 = malloc(2 * sizeof(char));
                        sub1[0] = tmp[i * 8];
                        sub1[1] = tmp[i * 8 + 1];
                        sub2[0] = tmp[i * 8 + 2];
                        sub2[1] = tmp[i * 8 + 3];
                        sub3[0] = tmp[i * 8 + 4];
                        sub3[1] = tmp[i * 8 + 5];
                        sub4[0] = tmp[i * 8 + 6];
                        sub4[1] = tmp[i * 8 + 7];
                        ip->s6_addr[i * 4] = strtoul(sub4, &endptr, 16);
                        ip->s6_addr[i * 4 + 1] = strtoul(sub3, &endptr, 16);
                        ip->s6_addr[i * 4 + 2] = strtoul(sub2, &endptr, 16);
                        ip->s6_addr[i * 4 + 3] = strtoul(sub1, &endptr, 16);
                     }
                     inet_ntop(AF_INET6, ip, ipv6->remote_addr, INET6_ADDRSTRLEN);
                }
                else if ( index_field == 4 ) {
                    ipv6->remote_port = convertHex2DecPort(tmp);
                }
                else if ( index_field == 5 ) {
                    strcpy(ipv6->connect_stat, tmp);
                }
                else if ( index_field == 6 ) {
                    strcpy(ipv6->trans_queue, tmp);
                }
                else if ( index_field == 7 ) {
                    strcpy(ipv6->rec_queue, tmp);
                }
                else if ( index_field == 8 ) {
                    strcpy(ipv6->timer_act, tmp);
                }
                else if ( index_field == 9 ) {
                    strcpy(ipv6->jiff_until_expires, tmp);
                }
                else if ( index_field == 10 ) {
                    strcpy(ipv6->unrecovered_timeout, tmp);
                }
                else if ( index_field == 11 ) {
                    char *endptr;
                    ipv6->uid = strtoul(tmp, &endptr, 10);
                }
                else if ( index_field == 12 ) {
                    char *endptr;
                    ipv6->timeout_number = strtoul(tmp, &endptr, 10);
                } 
                else if ( index_field == 13 ) {
                    char *endptr;
                    ipv6->inode = strtoul(tmp, &endptr, 10);
                }
                else if ( index_field == 14 ) {
                    char *endptr;
                    ipv6->socket_ref_count = strtoul(tmp, &endptr, 10);
                }
                else if ( index_field == 15 ) {
                    strcpy(ipv6->loc_socket, tmp);
                    ptr->data = ipv6;
                    ptr->next = malloc(sizeof(ipv6_node));
                    ptr = ptr->next;
                    ipv6 = malloc(sizeof(ipv6_struct));
                    memset(tmp, '\0', sizeof(tmp));
                    index_tmp = 0;
                    index_field = 0;
                    flushline = 1;
                    continue;
                } 
            
                memset(tmp, '\0', sizeof(tmp));
                index_tmp = 0;
                index_field++;
            }

        }
        else {
            tmp[index_tmp++] = c;
        }
    
    }

    return ip_list_header;
}

int isDigitDirName(char* dir) {
    int digit = 1;
    for ( int i = 0 ; i < strlen(dir) ; i++ ) {
        if ( !isdigit(dir[i] ) )
            digit = 0;
            return digit;
    }

    return digit;
}

char* getCorrespondingProcess(unsigned long inode) {
    DIR* proc_dir = opendir("/proc");
    struct dirent* traveler;
    int found = 0;
    char* result = malloc(512*sizeof(char)); 
    
    while( ( traveler = readdir(proc_dir) ) != NULL ) {
        
        if ( isDigitDirName(traveler->d_name) ) {
            char tmp[256];
            char buf[256];
            strcpy(tmp, "/proc");
            strcat(tmp, "/");
            strcat(tmp, traveler->d_name);
            strcat(tmp, "/fd");
            DIR* pid_dir = opendir(tmp);
            struct dirent* walker;
            if ( pid_dir != NULL ) {
                while ( ( walker = readdir(pid_dir) ) != NULL ) {
                    strcpy(tmp, "/proc");
                    strcat(tmp, "/");
                    strcat(tmp, traveler->d_name);
                    strcat(tmp, "/fd/");
                    if ( walker->d_type == DT_LNK ) {
                        unsigned long linked_inode;
                        strcat(tmp, walker->d_name);
                        if (readlink(tmp, buf, sizeof(buf)) < 0) {
                            perror("readlink() error");
                        }
                        else { 
                            sscanf(buf, "socket:[%lu]", &linked_inode);
                            if ( linked_inode == inode ) {
                                found = 1;
                            }
                        }
                    }
                    
                    if ( found ) {
                        strcpy(tmp, "/proc");
                        strcat(tmp, "/");
                        strcat(tmp, traveler->d_name);
                        strcat(tmp, "/cmdline");
                        FILE* cmdline = fopen(tmp, "r");
                        char c;
                        int index = 0;
                        strcpy(result, traveler->d_name);
                        strcat(result, "/");
                        index = strlen(result);
                        while( (c=fgetc(cmdline)) != EOF ) 
                            result[index++] = c;
                        fclose(cmdline);
                        return result;
                    }
                }
            }
            closedir(pid_dir);
        }
    }
    
    closedir(proc_dir); 

    return result;
}



void readTCP4() {
    char *tmp = malloc( 3000 * sizeof(char) );
    FILE *pFile;
    pFile = fopen("/proc/net/tcp", "r");
    ipv4_node *ip_list = parseIPv4(pFile);
    while ( ip_list->data != NULL ) {
        char* local_ip = ip_list->data->local_addr;
        int local_port = ip_list->data->local_port;
        char* remote_ip = ip_list->data->remote_addr;
        int remote_port = ip_list->data->remote_port;
        char* process = getCorrespondingProcess(ip_list->data->inode); 
        if ( remote_port == 0 )
            printf("tcp\t%s:%d\t\t\t%s:*\t\t\t%s\n", local_ip, local_port, remote_ip, process);
        else
            printf("tcp\t%s:%d\t\t\t%s:%d\t\t\t%s\n", local_ip, local_port, remote_ip, remote_port, process);

        
        ip_list = ip_list -> next;
    }

    fclose(pFile);
}

void readTCP6() {
    FILE *pFile;
    char *tmp = malloc( 3000 * sizeof(char) );
    pFile = fopen("/proc/net/tcp6", "r");
    ipv6_node *ip_list = parseIPv6(pFile);
    while ( ip_list->data != NULL ) {
        char* local_ip = ip_list->data->local_addr;
        int local_port = ip_list->data->local_port;
        char* remote_ip = ip_list->data->remote_addr;
        int remote_port = ip_list->data->remote_port ;
        char* process = getCorrespondingProcess(ip_list->data->inode); 
        if ( remote_port == 0 )
            printf("tcp6\t%s:%d\t\t\t%s:*\t\t\t%s\n", local_ip, local_port, remote_ip, process);
        else
            printf("tcp6\t%s:%d\t\t\t%s:%d\t\t\t%s\n", local_ip, local_port, remote_ip, remote_port, process);

        
        
        ip_list = ip_list -> next;
    }

    fclose(pFile);
}

void readUDP4() {
    FILE *pFile;
    char *tmp = malloc( 3000 * sizeof(char) );
    pFile = fopen("/proc/net/udp", "r");
    ipv4_node *ip_list = parseIPv4(pFile);
    while ( ip_list->data != NULL ) {
        char* local_ip = ip_list->data->local_addr;
        int local_port = ip_list->data->local_port;
        char* remote_ip = ip_list->data->remote_addr;
        int remote_port = ip_list->data->remote_port;
        char* process = getCorrespondingProcess(ip_list->data->inode); 
        if ( remote_port == 0 )
            printf("udp\t%s:%d\t\t\t%s:*\t\t\t%s\n", local_ip, local_port, remote_ip, process);
        else
            printf("udp\t%s:%d\t\t\t%s:%d\t\t\t%s\n", local_ip, local_port, remote_ip, remote_port, process);
       
        
        
        ip_list = ip_list -> next;
    }

    fclose(pFile);
}

void readUDP6() {
    FILE *pFile;
    char *tmp = malloc( 3000 * sizeof(char) );
    pFile = fopen("/proc/net/udp6", "r");
    ipv6_node *ip_list = parseIPv6(pFile);
    while ( ip_list->data != NULL ) {
        char* local_ip = ip_list->data->local_addr;
        int local_port = ip_list->data->local_port;
        char* remote_ip = ip_list->data->remote_addr;
        int remote_port = ip_list->data->remote_port;
        char* process = getCorrespondingProcess(ip_list->data->inode); 
        if ( remote_port == 0 )
            printf("udp6\t%s:%d\t\t\t%s:*\t\t\t%s\n", local_ip, local_port, remote_ip, process);
        else
            printf("udp6\t%s:%d\t\t\t%s:%d\t\t\t%s\n", local_ip, local_port, remote_ip, remote_port, process);
        
      

        ip_list = ip_list -> next;
    }

    fclose(pFile);
}



#endif
