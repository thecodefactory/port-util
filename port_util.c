/*
  Written by Neill Miller (neillm@thecodefactory.org)

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

  ----------------------
  Compile on Linux with:
  gcc port_util.c -o port_util

  Example run:
  ./port_util -i 192.168.1.100 -p 22,80,443,9999
  ----------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#define MAX_IP_LEN       16
#define MAX_NUM_PORTS    16
#define MAX_COMMAND_LEN 512
#define MAX_MSG_LEN     512

const char *PORT_DELIM = ",";
const char *LOG_FILE = "LOG";

char msg[MAX_MSG_LEN];

typedef struct
{
    char ip_addr[MAX_IP_LEN];
    int ports[MAX_NUM_PORTS];
    int num_ports;
} host_data_t;

typedef struct
{
    char *service;
    int port;
} service_dictionary_t;

service_dictionary_t registered_services[] =
{ { "ftp", 21 }, { "ssh", 22 }, { "http", 80 }, { "https", 443 }, { NULL, 0 } };

char *lookup_system_service_by_port(int port)
{
    int i = 0;
    char *ret = "unknown";
    service_dictionary_t *cur_service = NULL;

    do
    {
        cur_service = &registered_services[i++];
        if (cur_service->service == NULL)
        {
            break;
        }
        if (cur_service->port == port)
        {
            ret = cur_service->service;
        }
    } while(1);

    return ret;
}

int check_on_service(char *ip_address, int port, FILE *log_fd)
{
    int ret = 0;
    struct sockaddr_in s_addr;
    int s_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_fd != -1)
    {
        memset(&s_addr, '0', sizeof(s_addr));
        s_addr.sin_family = AF_INET;
        s_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip_address, &s_addr.sin_addr) == 1)
        {
            if (connect(s_fd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == 0)
            {
                snprintf(msg, MAX_MSG_LEN, "Connection success, service is active!\n");
                fwrite(msg, strlen(msg), sizeof(char), log_fd);
            }
            else
            {
                snprintf(msg, MAX_MSG_LEN, "Connection failed (%s)\n", strerror(errno));
                fwrite(msg, strlen(msg), sizeof(char), log_fd);
                if (errno == ECONNREFUSED)
                {
                    // attempt to restart service ... assuming someone
                    // is silly enough to allow password-less root ssh access
                    char cmd[MAX_COMMAND_LEN] = {0};
                    snprintf(cmd, MAX_COMMAND_LEN, "ssh root@%s \"service %s start\"",
                             ip_address, lookup_system_service_by_port(port));
                    snprintf(msg, MAX_MSG_LEN, "Attempting to restart service with command: %s\n", cmd);
                    fwrite(msg, strlen(msg), sizeof(char), log_fd);
                    system(cmd);
                }
                ret = 1;
            }
        }
        else
        {
            printf("Invalid or unsupported network address: %s\n", ip_address);
            ret = 1;
        }
    }
    return ret;
}

int check_host_data_status(host_data_t *hd)
{
    int i = 0;
    int ret = 0;

    FILE *log_fd = fopen(LOG_FILE, "a");
    if (log_fd)
    {
        time_t t;
        time(&t);

        snprintf(msg, MAX_MSG_LEN, "-------------------------------------------------\n");
        fwrite(msg, strlen(msg), sizeof(char), log_fd);
        snprintf(msg, MAX_MSG_LEN, "Starting system scan at %s", asctime(localtime(&t)));
        fwrite(msg, strlen(msg), sizeof(char), log_fd);
        snprintf(msg, MAX_MSG_LEN, "-------------------------------------------------\n");
        fwrite(msg, strlen(msg), sizeof(char), log_fd);

        for(i = 0; i < hd->num_ports; i++)
        {
            snprintf(msg, MAX_MSG_LEN, "Checking port %d on %s\n", hd->ports[i], hd->ip_addr);
            fwrite(msg, strlen(msg), sizeof(char), log_fd);
            ret += check_on_service(hd->ip_addr, hd->ports[i], log_fd);
        }
        fclose(log_fd);
    }
    return ret;
}

int parse_cmdline_args(int argc, char **argv, host_data_t *hd)
{
    int c = 0;
    while((c = getopt (argc, argv, "i:p:")) != -1)
    {
        switch (c)
        {
            case 'i':
            {
                snprintf((char *)&(hd->ip_addr), MAX_IP_LEN, "%s", optarg);
                break;
            }
            case 'p':
            {
                char *cur_port = strtok(optarg, PORT_DELIM);
                do
                {
                    if (cur_port)
                    {
                        hd->ports[hd->num_ports++] = atoi(cur_port);
                        //printf("Got Port[%d] = %d\n", hd->num_ports, atoi(cur_port));
                        if (hd->num_ports > MAX_NUM_PORTS)
                        {
                            break;
                        }
                    }
                } while(cur_port = strtok(NULL, PORT_DELIM));
                break;
            }
            default:
                abort ();
        }
    }
    return ((strlen(hd->ip_addr) && (hd->num_ports)) ? 0 : 1);
}

int main(int argc, char **argv)
{
    int ret = 0;
    host_data_t hd;
    memset(&hd, 0, sizeof(host_data_t));

    if (parse_cmdline_args(argc, argv, &hd) == 0)
    {
        ret = check_host_data_status(&hd);
    }
    else
    {
        printf("Usage: %s -i IP-ADDRESS -p PORT1,PORT2,PORTN\n", argv[0]);
    }
    return ret;
}
