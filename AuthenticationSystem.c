//Author: Joshua Shu
//This program simulates a login system by asking for an email and password from a user and then comparing it to a csv of valid logins and passwords.
//Note: Trims all inputs and only works for IPv4 IP addresses. Email and passwords are limited to 50 characters in length.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define HASH_TABLE_SIZE 1000

typedef struct HashNode {
    char email[50];
    char password[50];
    struct HashNode *next;
} HashNode;

HashNode *hashTable[HASH_TABLE_SIZE];

unsigned int hash(const char *key) {
    int c;
    unsigned long hash = 5381; //using 5381 since apparently this is a good seed value according to djb2
    
    while ((c = *key++)) {
        hash = ((hash << 5) + hash) + c;
    }

    return hash % HASH_TABLE_SIZE;
}

void insert(const char *email, const char *password) {
    unsigned int index = hash(email);
    HashNode *newNode = (HashNode *)malloc(sizeof(HashNode));

    strcpy(newNode->email, email);
    strcpy(newNode->password, password);

    newNode->next = hashTable[index];
    hashTable[index] = newNode;
}

HashNode *search(const char *email, const char *password) {
    unsigned int index = hash(email);
    HashNode *current = hashTable[index];

    while (current) {
        if (strcmp(current->email, email) == 0 && strcmp(current->password, password) == 0) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

void loadCredentials(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("ERROR: Could not open login and password file.");
        exit(EXIT_FAILURE);
    }

    char line[200];
    while (fgets(line, sizeof(line), file)) {
        char *email = strtok(line, ",");
        char *password = strtok(NULL, "\n");

        if (email && password) {
            while (*email == ' ') email++;
            email[strcspn(email, "\r\n")] = '\0';

            while (*password == ' ') password++;
            password[strcspn(password, "\r\n")] = '\0';

            insert(email, password);
        }
    }

    fclose(file);
}

void getTimestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", t);
}

void getIPAddress(char *buffer, size_t size) { //IPv4 only and it only grabs the first IP it can find since I don't know how to make it find the actual IP that's in use
    int family;
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("ERROR: Could not retrieve IP address.");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            const char *ip = inet_ntoa(addr->sin_addr);
            strncpy(buffer, ip, size);
            buffer[size - 1] = '\0';
            break;
        }
    }

    freeifaddrs(ifaddr);
}

void updateLog(const char *filename, const char *email, int success) {
    FILE *file = fopen(filename, "a");
    if (!file) {
        perror("ERROR: Could not open log file.");
        exit(EXIT_FAILURE);
    }

    char timestamp[20];
    char ip[16]; //16 since this isn't designed to support IPv6 addresses

    getTimestamp(timestamp, sizeof(timestamp));
    getIPAddress(ip, sizeof(ip));

    fprintf(file, "%s, %s, %s, %s\n", email, success ? "Success" : "Fail", timestamp, ip);
    fclose(file);
}

int main() {
    char email[50];
    char password[50];
    int attempts = 0;

    const char *inputFile = "LoginsAndPasswords.txt";
    const char *logFile = "signIn.txt";

    loadCredentials(inputFile);

    while (attempts < 3) {
        printf("Enter login email: ");
        scanf("%s", email);
        printf("Enter password: ");
        scanf("%s", password);

        if (search(email, password)) {
            printf("Login successful.\n");
            updateLog(logFile, email, 1);
            
            return 0;
        } else {
            printf("ERROR: Invalid login. Please try again.\n");
            updateLog(logFile, email, 0);
            attempts++;
        }
    }

    printf("ERROR: Three consecutive failed login attempts detected. You are locked out of further attempts for one hour.\n");

    return 0;
}