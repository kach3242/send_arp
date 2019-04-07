all : send_arp

send_arp : main.o
		g++ -g -o send_arp main.o -lpcap

main.o : main.cpp send_arp.h
		g++ -g -c -o main.o main.cpp

clean :
		rm -f send_arp
		rm -f *.o

