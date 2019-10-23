C=btsnoop_parse
GCC=gcc
SEQ=`echo ${RANDOM}`
all:
	$(GCC) -o $(C).elf $(C).c -lbluetooth

clean:
	rm -f *.elf
test:
	find / -type f -iname btsnoop_hci* ./$(C).elf {} \; 2> /dev/null | less
backup:
	cp $(C).c $(C).c.$(SEQ)

