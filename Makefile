all : send_arp

send_arp : main.o getmac.o
		g++ -g -o send_arp main.o getmac.o -lpcap

main.o : main.cpp send_arp.h
		g++ -g -c -o main.o main.cpp

getmac.o : getmac.cpp send_arp.h
		g++ -g -c -o getmac.o getmac.cpp

clean :
		rm -f send_arp
		rm -f *.o

