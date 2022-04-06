main: main.o rawSocSniffer.o rawSocket.o
	g++ -o main main.o rawSocSniffer.o rawSocket.o


main.o: main.cpp
	g++ -c main.cpp

rawSocSniffer.o: rawSocSniffer.cpp
	g++ -c rawSocSniffer.cpp

rawSocket.o: rawSocket.cpp
	g++ -c rawSocket.cpp

libpcapSniffer: libpcapSniffer.cpp
	g++ -o libpcapSniffer libpcapSniffer.cpp -lpcap

clean:
	rm  *.o main libpcapSniffer