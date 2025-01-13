CFLAGS += -Wall -Wextra -Wimplicit-fallthrough -Werror \
	-Os -fanalyzer -fdata-sections -ffunction-sections

#CFLAGS += -DKERMIT_LINK_ECHO
#CFLAGS += -DKERMIT_LINK_CTRL
#CFLAGS += -DKERMIT_LINK_7BIT

all: server client tool

server:
	$(CC) $(CFLAGS) kermit.c kmux-server.c -o kmux-server

client:
	$(CC) $(CFLAGS) kermit.c kmux-client.c -o kmux-client

tool:
	$(CC) $(CFLAGS) kermit.c kmux-tool.c -o kmux-tool

clean:
	rm -fv kmux-server kmux-client kmux-tool rand rand.enc rand.dec
