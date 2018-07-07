Target = myping

CF = send_icmp.c other.c

$(Target):
	gcc -o $(Target) $(CF)

play  :
	sudo ./$(Target) 192.168.3.1

clean :
	rm -rf *.o $(Target)

