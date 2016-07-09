sum_test: main.o sum.o
	g++ -o sum_test main.o sum.o
sum.o: sum.h sum.cpp
	g++ -c -o sum.o sum.cpp
main.o: sum.h main.cpp
	g++ -c -o main.o main.cpp
clean:
	rm -f *.o sum_test
