CFLAGS += -Wall -Wextra -Wimplicit-fallthrough -Werror \
	-Os -fanalyzer -fdata-sections -ffunction-sections

all:
	$(CC) $(CFLAGS) kermit.c kermit_selftest.c kmux.c -o kmux

clean:
	rm -fv kmux kmux.exe
