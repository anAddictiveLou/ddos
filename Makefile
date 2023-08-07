all:
	gcc -o syn_flood syn_flood.c -lpthread
	gcc -o icmp_flood icmp_flood.c -lpthread


