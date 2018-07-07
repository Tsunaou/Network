Target = recv_icmp

CF = icmp_reply.c other.c

$(Target):
	gcc -o $(Target) $(CF)

play  :
	sudo ./$(Target)

clean :
	rm -rf *.o $(Target)

