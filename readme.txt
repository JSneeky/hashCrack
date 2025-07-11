hashCrack.c uses an md5 hashing algorithm, in md5.c and md5.h, to hash given passwords and rules and checks if they are 
contained within a given list of hashes.

Input:
./hashCrack MODE <INPUT1> <INPUT2> 

Modes:
-p - Hashes a given password 
       > e.g. ./hashCrack -p password1 
       > will give the output: 7c6a180b36896a0a8c02787eeafb0e4c
-f - Takes a file of passwords and checks if their respective hashes are contained within a file of hashes
       > e.g. ./hashCrack -f ./docs/hashes.txt ./docs/passwords.txt 
       > will return passwords that match the given hashes
-b - Bruteforce mode, creates all passwords for a given rule and checks if their hashes match those within a given file
       > e.g. ./hashCrack -b ./docs/hashes.txt %l%l%n%n
       > will return any passwords, that fit the rule (where %l is a letter and %n is a number) that match any of the hashes 
         contained within hashes.txt
-r - Takes a file of rules and creates passwords for those given rules and checks if their hashes match those within the given  
     file of hashes
       > e.g. ./hashCrack -r ./docs/hashes.txt ./docs/rules.txt 
       > will return any passwords, that fit any of the rules, that match any of the hashes within hashes.txt

Example files have been provided:
> passwords.txt - contains example passwords
> hashes.txt - contains over 2000 example hashes of unknown passwords
> rules.txt - contains example rules 

It is important to note that not all rules will return any passwords and the greater the number of letters and numbers 
within a rule, the longer it will take the program finish.

The number of passwords the program has to hash can be calculated by:
52^l * 10^n        (where l is the number of %l's and n is the number of %n's within a single rule)

The number of total checks the program has to make can be calculated by:
52^l * 10^n * h    (where l is the number of %l's, n is the number of %n's within a single rule and h is the number of hashes in hashes.txt)

Both of these are exponential and so will grow rapidly, meaning that any rule larger than either 5 letters or numbers, or some combination of 
5 letters or numbers, will take a very long time. E.g. the rule %l%l%l%l%n%n will have to make 1,462,323,200,000 checks, for a file that has 
~2000 hashes.