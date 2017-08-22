APP = gpt_partition_move
SRC = main.c
CC ?= gcc

$(APP): $(SRC) Makefile
	$(CC) -o $(APP) -O2 $(SRC)

clean:
	rm -f $(APP)
