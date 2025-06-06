#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *query_string = getenv("QUERY_STRING");
    if (query_string == NULL) {
        printf("Content-Type: text/plain\r\n\r\nError: No query string provided.\n");
        return 1;
    }

    char *num1_str = NULL;
    char *num2_str = NULL;
    char *op_str = NULL;
    char *token;
    char *rest = query_string;

    while ((token = strtok_r(rest, "&", &rest)) != NULL) {
        if (strncmp(token, "num1=", 5) == 0) {
            num1_str = token + 5;
        } else if (strncmp(token, "num2=", 5) == 0) {
            num2_str = token + 5;
        } else if (strncmp(token, "op=", 3) == 0) {
            op_str = token + 3;
        }
    }

    if (num1_str == NULL || num2_str == NULL || op_str == NULL) {
        printf("Content-Type: text/plain\r\n\r\nError: Missing parameters.\n");
        return 1;
    }

    int num1 = atoi(num1_str);
    int num2 = atoi(num2_str);
    int result;

    if (strcmp(op_str, "add") == 0) {
        result = num1 + num2;
    } else if (strcmp(op_str, "subtract") == 0) {
        result = num1 - num2;
    } else if (strcmp(op_str, "multiply") == 0) {
        result = num1 * num2;
    } else if (strcmp(op_str, "divide") == 0) {
        if (num2 == 0) {
            printf("Content-Type: text/plain\r\n\r\nError: Division by zero.\n");
            return 1;
        }
        result = num1 / num2;
    } else {
        printf("Content-Type: text/plain\r\n\r\nError: Invalid operation.\n");
        return 1;
    }

    printf("Content-Type: text/plain\r\n\r\n%d", result);

    return 0;
}