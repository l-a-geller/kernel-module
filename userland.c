#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SYS_HELLOWORLD 440
#define COMMANDS_COUNT 2
#define BUF_SIZE 256

const char* commands[COMMANDS_COUNT] = { "bpf", "page" };
const char* structure_names[COMMANDS_COUNT] = { "bpf_map_memory", "page" };

void print_help() {
    printf("Welcome. Here you can get information about such kernel structures as:\n");
    printf("page - please enter page\n");
    printf("bpf_map_memory - please enter bpf\n");
}

void get_input(char** input) {
    scanf("%s", *input);
}

int is_command(char* input) {
    for (size_t i=0; i < COMMANDS_COUNT; i++) {
        if (strcmp(commands[i], input) == 0) return i;
    }
    return -1;
}

int get_option() {
    char* input;
    get_input(&input);
    int command = is_command(input);
    while (command == -1) {
        printf("Invalid input, enter your request again\n");
        get_input(&input);
        command = is_command(input);
    }
    return command;
}

int main() {

    FILE *proc;
    char *line = NULL;
    size_t len = 0;
    long syscall_status;

    print_help();

    int option = get_option();
    char* buffer = malloc(sizeof (char) * BUF_SIZE);
    syscall_status = syscall(SYS_HELLOWORLD, option, buffer, BUF_SIZE);
    if (syscall_status < 0) {
        printf("Problem while executing syscall\n");
    }
    fwrite(buffer, 1, BUF_SIZE, stdout);
    free(line);
    return 0;
}
