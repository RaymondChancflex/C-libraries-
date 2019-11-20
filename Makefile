all: main

main:	main.cpp ecp.o
	g++ -std=c++11 main.cpp ecp.o -o main -lboost_system -lcrypto -lssl -lcpprest -lgmp

clean:
	rm -rf ./ecp.o
	rm -rf ./main
