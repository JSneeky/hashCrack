#include "md5.h"
#include "md5.c"
#include <stdbool.h>

#define MAX 100
#define EXIT_CODE 1

//---------------------------------------- Hash File ---------------------------------------
void error() {
    fprintf(stderr, "Input error.\n");
    exit(EXIT_CODE);
}

/*
 * Checks that the file exists and can/has been opened without error
 */
FILE *fopenCheck(char *filename, char *mode) {
    FILE *f = fopen(filename, mode);
    if (f != NULL) return f;
    fprintf(stderr, "Can't open %s.\n", filename);
    exit(EXIT_CODE);
    
    return 0;
}

/*
 * Compares two hashes 
 */
bool compareHash(char hash[], char passHash[]) {
    bool compare = true;
    for (int i = 0; i < 16; i++) {
        if (hash[i] != passHash[i]) compare = false;
    }
    return compare;
}

/*
 * Condenses a 32 character hexadecimal string into a 16 char array by converting pairs
 * of hexadecimal digits into their decimal values
 */
void convert(char *hash) {
    char a, b;
    int j = 0;
    for (int i = 0; i < 33; i += 2, j++) {
        // Converts the first ASCII character into its decimal counterpart, i.e. a = 10, b = 11, etc.
        if (hash[i] >= 'a' && hash[i] <= 'f') {
            a = (hash[i] - 'a') + 10;
        }
        else a = hash[i] - '0';

        // Converts the second ASCII character into its decimal counterpart, i.e. a = 10, b = 11, etc.
        if (hash[i + 1] >= 'a' && hash[i + 1] <= 'f') {
            b = (hash[i + 1] - 'a') + 10;
        }
        else b = hash[i + 1] - '0';

        // Calculates the final decimal value of the two hexadecimal digits
        hash[j] = (a * 16) + b;
    }

    hash[16] = '\0';
}

/*
 * Checks a file of passwords against a file of unknown hashes for matches
 */
void hashFile(FILE *passwords, FILE *hashes) {
    char line1[11], line2[34];
    uint8_t result[16];
    
    fgets(line1, 11, passwords);
    while (! feof(passwords)) {
        int len = strlen(line1);
        line1[len - 1] = '\0';
        // Hashes the current password
        md5String(line1, result);

        fseek(hashes, 0, SEEK_SET);
        fgets(line2, 34, hashes);
        // Compares the hashed password against each hash in the given hash file for matches
        while (! feof(hashes)) {
            convert(line2);
            // If the hashes match, print the password and it's hash
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

//---------------------------------------- Bruteforce ---------------------------------------

/*
 * Checks a known password against a file of unknown hashes for matches
 */
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

// Calculates the ith password in the set of possible passwords for a given rule
void password(char *rule, char *pass, unsigned long i, int length) {
    int k = 0;
    unsigned long pos = i;
    char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char numbers[] = "0123456789";

    for (int j = 0; j < length; j += 2, k++){
        // If the rule requires a letter, generate the corresponding letter 
        if (rule[j] == '%' && (j + 1) < length) {
            if (rule[j + 1] == 'l') {
                pass[k] = letters[pos % 52];
                pos /= 52;
            }
            // Else generate the corresponding number
            else if (rule[j + 1] == 'n') {
                pass[k] = numbers[(pos % 10)];
                pos /= 10;
            }
        }
    }
    pass[length - (length / 2)] = '\0';
}

/*
 * Runs the bruteforce algorithm for each possible password for a given rule
 */
void hashCrack(char *rule, unsigned long totalcomb, char *hash) {
    int length = strlen(rule);
    char pass[length];
    uint8_t result[16];

    for (unsigned long i = 0; i < totalcomb; i++) {
        // Generate ith password for the given rule
        password(rule, pass, i, length);
        // Hash the password
        md5String(pass, result);
        FILE *hashes = fopenCheck(hash, "r");
        // Check the hashed password against the file of hashes
        processHash(hashes, pass, result);
    }
}

/*
 * Counts the number of letters and numbers a rule requires
 */
void rules(char *rule, int *settings) {
    int length = strlen(rule);
    for (int i = 0; i < length; i++) {

        if (rule[i] == '%' && (i + 1) < length) {
            if (rule[i + 1] == 'l') settings[0]++; 
            else if (rule[i + 1] == 'n') settings[1]++;
        }

    }
}

/*
 * Calculates the total number of combinations for a given rule and then runs the bruteforce algorithm
 */
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

//---------------------------------------- Rules ----------------------------------------

/*
 * Runs the bruteforce algorithm for each rule in the rules file
 */
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

//---------------------------------------- Hash String ---------------------------------------

/*
 * Prints the hash of a given password 
 */
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
