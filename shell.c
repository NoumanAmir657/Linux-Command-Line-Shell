#include <stdio.h>
#include <sys/wait.h> //symbolic constants for waitpid()
#include <unistd.h> //for fork() chdir() and pid_t
#include <stdlib.h> //for dynamic memory allocation e.g malloc
#include <string.h> //for string related functions.
#include <signal.h> //for handling signals

#define SHELL_LINE_BUFSIZE 1024 //buffer size for storing line
#define SHELL_TOK_BUFSIZE 64 //token buffer size for arguments.
#define TOKENS " \t\r\n\a" //delimiters
#define SIZE 50
FILE *profile  = NULL; //file pointer for user profile
//Structure for User
struct user{
    char username[SIZE];
    char password[SIZE];
};
void create_account(void); //creates user account
void display(void); //for display
int login(void); //login of user
void add_to_file(char *); //summary of commands
void print_user_history(void);
void print_instructions(void); //instructions manual

void shell_loop(void); //main loop of shell
char *shell_read_line(void); //read line from stdin
char **get_arguments(char *); //seperate arguments from the command
int shell_execute(char **); //executing of shell command
int shell_launch(char **); //launching of shell
void getpath(void); //for printing path on the command line

//Builtin Commands Functions Declarations
int shell_cd(char **args); //changing directory function
int shell_help(char **args); //help function
int shell_exit(char **args); //for exiting shell

int shell_num_builtins(void); //builtin commands of shell

int process_line(char *, char ***, char ***);
int parsePipe(char *, char **); //for separating the pipe commands
int shell_execute_pipe(char **, char **); //for executing pipe commands

char *builtin_str[] = {"cd", "help", "exit"}; //List of builtin commands

int (*builtin_func[])(char **) = {&shell_cd, &shell_help, &shell_exit}; //function pointer for builtin functions


int main(int argc, char **argv){
    FILE *names_list = NULL;
    names_list = fopen("usernames.txt", "a"); //opens the file that contains usernames
    fclose(names_list);
    int choice;
    while (1){
        display();
        printf("Enter Choice: ");
        scanf("%d", &choice);
        getc(stdin);
        switch(choice){
            case 1:{
                create_account();
                break;
            }
            case 2:{
                if (login()){
                    shell_loop();
                    fclose(profile);
                }
                //run main loop
                chdir("/mnt/c/Users/HP/Desktop/Shell"); //to counter the cd problem with file opening
                break;
            }
            case 3:{
                print_user_history();
                break;
            }
            case 4:{
                print_instructions();
                break;
            }
            case 5:{
                exit(0); //to exit program
            }
        }
    }
    return 0;
}

void display(){
    system("clear");
    printf("\t\t Welcome to Command Line Shell \t\t\n");
    printf("1: Create Account\n");
    printf("2: Execute Shell Commands\n");
    printf("3: See User Command History\n");
    printf("4: Instructions Manual\n");
    printf("5: Exit\n");
}

void shell_loop(){
    char *line = NULL; //for storing line read from stdin
    char **args = NULL; //for storing arguments of commands
    char **args2 = NULL; //for storing arguments of commands
    int status; //flag value to exit the below loop
    int flag = 0; //used to decide whether command entered is with pipe or without pipe

    do {
        getpath(); //get the current directory and print it on stdout.
        printf("> ");
        line = shell_read_line(); //function called which return line read from stdin
        add_to_file(line);
        flag = process_line(line, &args, &args2);
        //args = get_arguments(line);
        if (flag == 0){ //for no pipe
            status = shell_execute(args);
            free(args); //freeing allocated memory
            //free(args2);
        }
        else { //for pipe
            status = shell_execute_pipe(args, args2);
            free(args);
            free(args2);
        }
        free(line);
    } while(status);
}

void getpath(void){
    char cwd[1024];
    getcwd(cwd, sizeof(cwd)); //fucntion to get the current directory
    printf("~%s", cwd);
}

char *shell_read_line(){
    int buffer_size = SHELL_LINE_BUFSIZE; //buffer size assigned to variable
    int position = 0;
    char *buffer = malloc(sizeof(char) * buffer_size); //dynamically allocated memory of 1024 bytes
    int c;

    //allocation error check
    if (buffer == NULL){
        fprintf(stderr, "shell: allocation error\n");
        exit(0);
    }

    while (1){
        c = getchar(); //reads a character
        
        if(c == EOF || c == '\n'){ //if end of line reached
            buffer[position] = '\0';
            return buffer;
        }
        else {
            buffer[position] = c;
        }
        position++;

        //if buffer memory allocation is exceeded
        if (position > buffer_size){
            buffer_size += SHELL_LINE_BUFSIZE; //increase buffer size
            buffer = realloc(buffer, buffer_size * sizeof(char)); //reallocate memory with new buffer size
            //reallocation error check
            if (buffer == NULL){
                fprintf(stderr, "shell: allocation error\n");
                exit(0);
            }    
        }
    }
}

int process_line(char *line, char ***args, char ***args2){
    char *strpiped[2]; //storing the pipe commands seperately
    int piped = 0; //flag to indicate whether a command has pipe in it or not.

    piped = parsePipe(line, strpiped); //to seperate the pipe commands

    if(piped == 1){
        *args = get_arguments(strpiped[0]); //get arguments for first pipe command
        *args2 = get_arguments(strpiped[1]); //get arguments for second pipe command
    }
    else{
        *args = get_arguments(line); //get arguments when no pipe command
    }
    return piped;
}

int parsePipe(char *line, char **strpiped){
    for (int i = 0; i < 2; ++i){
        strpiped[i] = strsep(&line, "|"); //strsep() seperates the pipe commands
        if (strpiped[i] == NULL){ //strsep returns NULL if no | found
            break;
        }
    }

    if (strpiped[1] == NULL){
        return 0; //no pipe in command
    }
    else{
        return 1; //pipe found
    }
}

char **get_arguments(char *line){
    int buffer_size = SHELL_TOK_BUFSIZE;
    int position = 0;
    char **tokens = malloc(buffer_size * sizeof(char)); //dynamic memory allocated for 2d array
    char *token; //for storing a single argument

    if (tokens == NULL){
        fprintf(stderr, "shell: allocation error\n");
        exit(0);
    }

    token = strtok(line, TOKENS); //first tokenization
    while (token != NULL){
        tokens[position] = token;
        position++;

        if (position >= buffer_size){
            buffer_size += SHELL_TOK_BUFSIZE;
            tokens = realloc(tokens, buffer_size * sizeof(char));

            if (tokens == NULL){
                fprintf(stderr, "shell: allocation error\n");
                exit(0);
            }
        }
        token = strtok(NULL, TOKENS); //further tokenization, NULL argument so that it starts tokenization from where it left of in first tokenization.
    }
    tokens[position] = NULL;
    return tokens;
}

int shell_execute(char **args){
    int i;

    if (args[0] == NULL){
        //An empty command was entered.
        return 1;
    }

    //loop through the builtin-commands and if the entered command matches with it then execute it.
    for (i = 0; i < shell_num_builtins(); i++){ 
        if(strcmp(args[0], builtin_str[i]) == 0){
            return (*builtin_func[i])(args);
        }
    }
    return shell_launch(args);
}

int shell_launch(char **args){
    pid_t pid, wpid; //pid_t is a typedef for signed int. used to represent process ids.
    int status;

    pid = fork(); //fork() divides the process into parent and child process.
    //fork() returns 0 for child process and id of child process for parent process

    if (pid == 0){
        //Child Process
        if (execvp(args[0], args) == -1){ //exce() fucntions are used to change a child process into a new process
            perror("shell");
        }
        exit(0);
    }
    else if(pid < 0){
        //error returned by fork()
        perror("shell");
    }
    else{
        //Parent Process
        do {
            wpid = waitpid(pid, &status, WUNTRACED); //WUNTRACED for seeing if child process is terminated
        } while(!WIFEXITED(status) && !WIFSIGNALED(status)); //WIFEEXITED returns non-zero value if child terminated with success.
        //WIFESIGNALED returns true if the child process was termianted by a signal
    }
    return 1;
}

int shell_execute_pipe(char **args, char **args2){
    int pipefd[2], status, status2; //pipe file descriptor array
    pid_t p1, p2, wpid, wpid2; //for id of each child process

    if (pipe(pipefd) < 0){ //creates a file descriptor array for read and write end of pipe
        fprintf(stderr, "\nPipe could not be initialized");
        return 0;
    }

    p1 = fork(); //creates first child process
    if (p1 < 0){
        perror("shell");
        return 0;
    }

    else if (p1 == 0){
        //Child 1 executing..
        close(pipefd[0]); //close the read end of pipe 
        dup2(pipefd[1], STDOUT_FILENO); //gives pipefd[1](write end of pipe) the file descriptor of stdout.
        close(pipefd[1]); //closes write end of pipe

        if (execvp(args[0], args) < 0){
            perror("shell");
        }
        exit(0);
    }
    else {
        // parent executing
        do {
            wpid = waitpid(p1, &status, WUNTRACED);
        } while(!WIFEXITED(status) && !WIFSIGNALED(status));
        
        p2 = fork();

        if (p2 < 0){
            perror("shell");
            return 0;
        }

        //Child 2 executing
        else if (p2 == 0){
            close(pipefd[1]); //close the read end of pipe
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[0]);
            if (execvp(args2[0], args2) < 0){
                perror("shell");
            }
            exit(0);
        }
        else {
            do {
                wpid2 = waitpid(p1, &status2, WUNTRACED);
            } while(!WIFEXITED(status2) && !WIFSIGNALED(status2));
        }
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return 1;
}

int shell_num_builtins(){
    return sizeof(builtin_str) / sizeof(char *);
}

int shell_cd(char **args){
    if (args[1] == NULL){
        fprintf(stderr, "shell: expected argument to \"cd\"\n");
    }
    else{
        if (chdir(args[1]) != 0){
            perror("shell");
        }
    }
    return 1;
}

int shell_help(char **args){
    int i;
    printf("New Shell\n");
    printf("Type program names and arguments, and hit enter.\n");
    printf("The following are built in:\n");

    for (i = 0; i < shell_num_builtins(); i++){
        printf("  %s\n", builtin_str[i]);
    }

    printf("Use the man command for information on other programs.");
    return 1;
}

int shell_exit(char **args){
    return 0;
}

void create_account(){
    struct user a;
    struct user b;
    char temp[100];
    char found = 'F';
    FILE *names_list = NULL;
    FILE *new = NULL;
    while (1){
        found = 'F';
        printf("Enter Username: ");
        scanf("%s", a.username);
        printf("Enter Password: ");
        scanf("%s", a.password);
        names_list = fopen("usernames.txt", "r");
        //check whether name already exists in username.txt or not
        while (1){
            if (fread(&b, sizeof(b), 1, names_list) == 0){
                break;
            }
            if (strcmp(b.username, a.username) == 0){
                found = 'T';
                break;
            }
        }
        fclose(names_list);
        if (found == 'F'){
            names_list = fopen("usernames.txt", "a");
            sprintf(temp, "./Users/%s.txt", a.username);
            new = fopen(temp, "w");
            fwrite(&a, sizeof(a), 1, names_list);
            fclose(new);
            fclose(names_list);
            printf("\nAccount Created");
            getc(stdin);
            getc(stdin);
            break;
        }
        else if(found == 'T'){
            printf("Username already exists!!! Enter a new Username.\n");
        }
    }
}

int login(){
    char temp[100];
    struct user a;
    struct user b;
    char found = 'F';
    FILE *names_list = NULL;
    FILE *new = NULL;

    printf("Enter Username: ");
    scanf("%s", a.username);
    printf("Enter Password: ");
    scanf("%s", a.password);
    names_list = fopen("usernames.txt", "r+");
    while (1){
        if (fread(&b, sizeof(b), 1, names_list) == 0){
            break;
        }
        if (strcmp(b.username, a.username) == 0){
            found = 'T';
            break;
        }
    }

    fclose(names_list);
    if (found == 'T' && strcmp(b.password, a.password) == 0){
        sprintf(temp, "./Users/%s.txt", a.username);
        profile = fopen(temp, "a");
        printf("OK! You are logged in.\n");
        fflush(stdin);
        getc(stdin);
        getc(stdin);
        return 1;
    }
    else {
        printf("User does not exist or Password is wrong\n");
        fflush(stdin);
        getc(stdin);
        getc(stdin);
        return 0;
    }
}

void add_to_file(char *line){
    fprintf(profile, "%s\n", line); //writes the command in the User file.
}

void print_user_history(){
    struct user a;
    struct user b;
    char temp[100];
    char found = 'F';
    FILE *names_list = NULL;
    FILE *new = NULL;

    printf("Enter Username: ");
    scanf("%s", a.username);
    printf("Enter Password: ");
    scanf("%s", a.password);
    names_list = fopen("usernames.txt", "r");
    while (1){
        if (fread(&b, sizeof(b), 1, names_list) == 0){
            break;
        }
        if (strcmp(b.username, a.username) == 0){
            found = 'T';
            break;
        }
    }

    fclose(names_list);
    if (found == 'T' && strcmp(b.password, a.password) == 0){
        sprintf(temp, "./Users/%s.txt", a.username);
        new = fopen(temp, "r");
        printf("\t\tCommand Summary\n");
        while (fgets(temp, 100, new) != NULL){
            printf("\t\t%s", temp);
        }
        fclose(new);
    }
    else {
        printf("User does not exist or Password is wrong\n");
    }
    fflush(stdin);
    getc(stdin);
    getc(stdin);
}

void print_instructions(void){
    FILE *ins = NULL;
    int c;
    ins = fopen("instructions.txt", "r");
    c = fgetc(ins);
    while (c != EOF){
        printf("%c", c);
        c = fgetc(ins);
    }
    fclose(ins);
    getc(stdin);
}