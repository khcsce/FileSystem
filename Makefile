# NAME: Khoa Quach, Joshua Futterman
# EMAIL: khoaquachschool@gmail.com, joshafuttcomp23@ucla.edu
# ID: 105123806,505347668
.SILENT:
CC = gcc
CFLAGS = -Wall -Wextra
default:
	$(CC) $(CFLAGS) -o lab3a lab3a.c

dist: 
	tar -cvzf lab3a-105123806.tar.gz lab3a.c ext2_fs.h README Makefile

clean: 
	rm -f *.tar.gz lab3a *.o *~

smoketest: default
	./lab3a trivial.img | sort > mine.csv
	cat < trivial.csv | sort > trivial_sorted.csv
	diff mine.csv trivial_sorted.csv
