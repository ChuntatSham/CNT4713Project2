#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#pragma pack(1)
char *format(char *name);

typedef struct sockaddr SA;

typedef struct
{
    unsigned short transaction_id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answers;
    unsigned short auths;
    unsigned short adds;
} Header;

typedef struct
{
    char *name;
    unsigned short type;
    unsigned short class;
} Query;

/************************************************
 *packet helper function
 *
 *
 ***********************************************/

/**/
// ./mydns cs.fiu.edu 202.12.27.33

int main(int argc, char **argv)
{

    if (argc != 3)
    {
        printf("usage:%s hostname rootip\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *hostname = argv[1];
    char serverip[255];
    strcpy(serverip, argv[2]);

    ssize_t retval = 0;
    int sockfd;
    retval = socket(AF_INET, SOCK_DGRAM, 0);
    if (retval == -1)
    {
        perror("create socket");
        exit(EXIT_FAILURE);
    }
    sockfd = retval;
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53);
    while (1)
    {
        printf("----------------------------\n");
        printf("DNS server to query: %s\n", serverip);
        retval = inet_aton(serverip, &(servaddr.sin_addr));
        if (retval == 0)
        {
            fprintf(stderr, "root ip is not valid\n");
            exit(EXIT_FAILURE);
        }

        unsigned char req[512];
        unsigned char resp[512];

        int len = 0;
        Header a = {htons(23), 0, htons(1), 0, 0, 0};
        Query q = {format(hostname), htons(1), htons(1)};
        memcpy(req, &a, sizeof(Header));
        len = len + sizeof(Header);
        memcpy(req + len, q.name, strlen(q.name) + 1);
        len = len + strlen(q.name) + 1;
        memcpy(req + len, &(q.type), 2);
        len += 2;
        memcpy(req + len, &(q.class), 2);
        len += 2;

        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        {
            printf("socket option  SO_RCVTIMEO not support\n");
            exit(1);
        }

        while (1)
        {
            retval = sendto(sockfd, req, len, 0, (SA *)(&servaddr), sizeof(servaddr));
            if (retval == 0)
            {
                perror("send to server failere");
                exit(EXIT_FAILURE);
            }
            ssize_t len1 = sizeof(servaddr);
            retval = recvfrom(sockfd, resp, 512, 0, (SA *)(&servaddr),
                              (socklen_t *)(&len1));
            if (retval < 0)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                    continue;
                else
                {
                    printf("recvfrom err:%d\n", errno);
                    exit(1);
                }
            }
            break;
        }
        Header *h = (Header *)resp;
        int answer_count = ntohs(h->answers);
        int auth_count = ntohs(h->auths);
        int add_count = ntohs(h->adds);
        printf("Reply received. Content overview:\n");
        printf("%02d Answers.\n", answer_count);
        printf("%02d Intermediate Name Servers.\n", auth_count);
        printf("%02d Additional Information Records.\n", add_count);
        printf("%d\n", len);
        printf("Answers Section:\n");
        unsigned char *index = resp + len;
        unsigned char *temp = resp + len;
        for (int i = 0; i < answer_count; i++)
        {
            int count = 0;
            char name[255];
            int is_offset = 0;
            int is_first = 1;
            while (1)
            {
                char c = *index;
                if (c == '\0')
                {
                    name[count++] = '\0';
                    break;
                }
                if (c > 0 && c < 64)
                {
                    index++;
                    if (is_offset == 0)
                        temp++;
                    if (is_first == 0)
                        name[count++] = '.';
                    is_first = 0;
                    for (int i = 0; i < c; i++)
                    {
                        name[count++] = *index;
                        index++;
                        if (is_offset == 0)
                            temp++;
                    }
                }
                else
                {
                    unsigned short offset = *((unsigned short *)index);
                    offset = ntohs(offset) & 16383;
                    if (is_offset == 0)
                        temp = index + 2;
                    index = resp + offset;
                    is_offset = 1;
                }
            }
            temp = temp + 10;
            char *answerip = inet_ntoa(*((struct in_addr *)temp));
            printf("Name:%s    IP: %s\n", name, answerip);
            temp = temp + 4;
            index = temp;
        }
        printf("Authoritive Section:\n");

        for (int i = 0; i < auth_count; i++)
        {
            int count = 0;
            char name[255];
            char servername[255];
            int is_first = 1;
            int is_offset = 0;
            while (1)
            {
                char c = *index;
                if (c == '\0')
                {
                    name[count++] = '\0';
                    break;
                }
                if (c > 0 && c < 64)
                {
                    index++;
                    if (is_offset == 0)
                        temp++;
                    if (is_first != 1)
                        name[count++] = '.';
                    is_first = 0;
                    for (int i = 0; i < c; i++)
                    {
                        name[count++] = *index;
                        index++;
                        if (is_offset == 0)
                            temp++;
                    }
                }
                else
                {
                    unsigned short offset = *((unsigned short *)index);
                    offset = ntohs(offset) & 16383;
                    if (is_offset == 0)
                        temp = index + 2;
                    index = resp + offset;
                    is_offset = 1;
                }
            }
            if (is_offset == 0)
            {
                index++;
                temp++;
            }
            temp = temp + 10;
            index = temp;
            count = 0;
            is_first = 1;
            is_offset = 0;
            while (1)
            {
                char c = *index;
                if (c == '\0')
                {
                    servername[count++] = '\0';
                    break;
                }
                if (c > 0 && c < 64)
                {
                    index++;
                    if (is_offset == 0)
                        temp++;
                    if (is_first != 1)
                        servername[count++] = '.';
                    is_first = 0;
                    for (int i = 0; i < c; i++)
                    {
                        servername[count++] = *index;
                        index++;
                        if (is_offset == 0)
                            temp++;
                    }
                }
                else
                {
                    unsigned short offset = *((unsigned short *)index);
                    offset = ntohs(offset) & 16383;
                    if (is_offset == 0)
                        temp = index + 2;
                    index = resp + offset;
                    is_offset = 1;
                }
            }
            printf("Name:%s    Name Server: %s\n", name, servername);
            if (is_offset == 0)
            {
                index++;
                temp++;
            }
            index = temp;
        }

        printf("Additional Information Section:\n");

        for (int i = 0; i < add_count; i++)
        {

            int count = 0;
            char name[255];
            int is_first = 1;
            int is_offset = 0;
            while (1)
            {
                char c = *index;
                if (c == '\0')
                {
                    name[count++] = '\0';
                    break;
                }
                if (c > 0 && c < 64)
                {
                    index++;
                    if (is_offset == 0)
                        temp++;
                    if (is_first == 0)
                        name[count++] = '.';
                    is_first = 0;
                    for (int i = 0; i < c; i++)
                    {
                        name[count++] = *index;
                        index++;
                        if (is_offset == 0)
                            temp++;
                    }
                }
                else
                {
                    unsigned short offset = *((unsigned short *)index);
                    offset = ntohs(offset) & 16383;
                    if (is_offset == 0)
                        temp = index + 2;
                    index = resp + offset;
                    is_offset = 1;
                }
            }
            if (is_offset == 0)
            {
                index++;
                temp++;
            }

            temp = temp + 8;
            unsigned short data_len = ntohs(*((unsigned short *)temp));
            temp = temp + 2;
            printf("Name:%s", name);
            if (data_len != 4)
            {
                temp = temp + data_len;
            }
            else
            {
                char *answerip = inet_ntoa(*((struct in_addr *)temp));
                printf("    IP: %s", answerip);
                temp = temp + 4;
                if (i == 0)
                    strcpy(serverip, answerip);
            }
            index = temp;
            printf("\n");
        }

        if (answer_count != 0)
            break;
    }
    return 0;
}

char *format(char *name)
{
    char *format_name = malloc(strlen(name) + 2);
    strcpy(format_name + 1, name);
    format_name[0] = '.';
    int len = strlen(name);
    char count = 0;
    for (int i = len; i >= 0; i--)
    {
        if (format_name[i] == '.')
        {
            format_name[i] = count;
            count = 0;
        }
        else
        {
            count++;
        }
    }
    return format_name;
}
