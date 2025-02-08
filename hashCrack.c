#include "md5.h"
#include "md5.c"
#include <stdbool.h>

#define MAX 100
#define EXIT_CODE 1

//----------------------------------------Hash File---------------------------------------
void error() {
    fprintf(stderr, "Input error.\n");
    exit(EXIT_CODE);
}

FILE *fopenCheck(char *filename, char *mode) {
    FILE *f = fopen(filename, mode);
    if (f != NULL) return f;
    fprintf(stderr, "Can't open %s.\n", filename);
    exit(EXIT_CODE);
    
    return 0;
}

bool compareHash(char hash[], char passHash[]) {
    bool compare = true;
    for (int i = 0; i < 16; i++) {
        if (hash[i] != passHash[i]) compare = false;
    }
    return compare;
}

void convert(char *hash) {
    char a, b;
    int j = 0;
    for (int i = 0; i < 33; i += 2, j++) {
        if (hash[i] >= 'a' && hash[i] <= 'f') {
            a = (hash[i] - 'a') + 10;
        }
        else a = hash[i] - '0';

        if (hash[i + 1] >= 'a' && hash[i + 1] <= 'f') {
            b = (hash[i + 1] - 'a') + 10;
        }
        else b = hash[i + 1] - '0';

        hash[j] = (a * 16) + b;
    }

    hash[16] = '\0';
}

void hashFile(FILE *passwords, FILE *hashes) {
    char line1[11], line2[34];
    uint8_t result[16];
    fgets(line1, 11, passwords);
    while (! feof(passwords)) {
        int len = strlen(line1);
        line1[len - 1] = '\0';
        md5String(line1, result);

        fseek(hashes, 0, SEEK_SET);
        fgets(line2, 34, hashes);
        while (! feof(hashes)) {
            convert(line2);
            if (compareHash(line2, (char *)result) == true) {
                printf("%s : ", line1);
                print_hash(result);
            }
            fgets(line2, MAX, hashes);
        }
        fgets(line1, MAX, passwords);
    }
}

void processFiles(char *passwords, char *hashes) {
    FILE *passes = fopenCheck(passwords, "r");
    FILE *hash = fopenCheck(hashes, "r");
    
    hashFile(passes, hash);
}

//----------------------------------------Bruteforce---------------------------------------

void processHash(FILE *hashes, char *pass, uint8_t result[]) {
    char hash[34];
    fgets(hash, 34, hashes);
    while (! feof(hashes)) {
        convert(hash);
        if (compareHash(hash, (char *)result) == true) {
            printf("%s : ", pass);
            print_hash(result);
        }
        fgets(hash, 34, hashes);
    }
}

void password(char *rule, char *pass, unsigned long i, int length) {
    int k = 0;
    unsigned long pos = i;
    char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char numbers[] = "0123456789";

    for (int j = 0; j < length; j += 2, k++){
        if (rule[j] == '%' && (j + 1) < length) {
            if (rule[j + 1] == 'l') {
                pass[k] = letters[pos % 52];
                pos /= 52;
            }
            else if (rule[j + 1] == 'n') {
                pass[k] = numbers[(pos % 10)];
                pos /= 10;
            }
        }
    }
    pass[length - (length / 2)] = '\0';
    //printf("%s\n", pass);
}

void hashCrack(char *rule, unsigned long totalcomb, char *hash) {
    int length = strlen(rule);
    char pass[length];
    uint8_t result[16];

    for (unsigned long i = 0; i < totalcomb; i++) {
        password(rule, pass, i, length);
        md5String(pass, result);
        FILE *hashes = fopenCheck(hash, "r");
        processHash(hashes, pass, result);
    }
}

void rules(char *rule, int *settings) {
    int length = strlen(rule);
    for (int i = 0; i < length; i++) {

        if (rule[i] == '%' && (i + 1) < length) {
            if (rule[i + 1] == 'l') settings[0]++; 
            else if (rule[i + 1] == 'n') settings[1]++;
        }

    }
}

void bruteforce(char *hash, char *rule) {
    int settings[] = {0, 0};
    rules(rule, settings);
    unsigned long totalcomb = 1;

    for (int i = 0; i < settings[0]; i++) {
        totalcomb *= 52;
    }

    for (int i = 0; i < settings[1]; i++) {
        totalcomb *= 10;
    }

    hashCrack(rule, totalcomb, hash);
}

//----------------------------------------Rules----------------------------------------
void bruteforceRule(char *hashes, FILE *rules) {
    char rule[12];

    fgets(rule, 12, rules);

    while (! feof(rules)) {
        int length = strlen(rule);
        rule[length - 1] = '\0';

        bruteforce(hashes, rule);
        fgets(rule, 12, rules);
    }
}

void ruleFile(char *hashes, char *rules) {
    FILE *rule = fopenCheck(rules, "r");

    bruteforceRule(hashes, rule);
}

//----------------------------------------Hash String---------------------------------------

void hashString(char *string) { 
    uint8_t result[16];
    md5String(string, result);
    printf("%s : ", string);
    print_hash(result);
}

int main(int n, char *args[n]) {
    //./hashCrack -p PASSWORD
    if ((strcmp(args[1], "-p") == 0) && (n == 3)) {
        hashString(args[2]);
    }
    //.hashCrack -f HASHES PASSWORDS
    else if ((strcmp(args[1], "-f") == 0) && (n == 4)) {
        processFiles(args[3], args[2]);
    }
    //./hashCrack -b HASHES RULE
    else if ((strcmp(args[1], "-b") == 0) && (n == 4)) {
        bruteforce(args[2], args[3]);
    }
    //./hashCrack -r HASHES RULES
    else if ((strcmp(args[1], "-r") == 0) && (n == 4)) {
        ruleFile(args[2], args[3]);
    }
    else error();
    return 0;
}
