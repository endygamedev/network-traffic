#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>


/* Maximum number of ports */
#define MAX_PORT 65535


/*
 * Checks if the string is a number.
 * Returns 1 if string is a number, 0 otherwise.
 * */
int is_number(char *arg)
{
    int flag = 1;
    for (int i = 0; i < (int)strlen(arg); i++) {
        if (!isdigit(arg[i])) {
            flag = 0;
            break;
        }
    }
    return flag;
}


/*
 * Checks if IP record is valid or not.
 * Returns EXIT_SUCCESS if all correct, EXIT_FAILURE otherwise.
 * */
int check_ip_record(char *ip)
{
    if (ip == NULL) {
        return EXIT_SUCCESS;
    }
    
    char *tmp = strdup(ip);

    char *token = strtok(tmp, ".");
    int number, count = 0;

    while (token != NULL) {
        if (count > 3) {
            fprintf(stderr, "Error: Invalid IP filter\n");
            exit(EXIT_FAILURE);
        }
        
        if (!is_number(token)) {
            fprintf(stderr, "Error: Invalid IP filter\n");
            exit(EXIT_FAILURE);
        }
        
        number = atoi(token);
        
        if (number > 255 || number < 0) {
            fprintf(stderr, "Error: Invalid IP filter\n");
            exit(EXIT_FAILURE);
        }

        token = strtok(NULL, ".");
        count++;
    }
    
    return EXIT_SUCCESS;
}


/*
 * Checks if UDP port is valid or not.
 * Returns EXIT_SUCCESS if all correct, EXIT_FAILURE otherwise.
 * */
int check_port(int port)
{
    if (port > MAX_PORT) {
        fprintf(stderr, "Error: Invalid UDP port filter\n");
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}
