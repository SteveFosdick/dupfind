CFLAGS = -O3 -Wall -I /usr/include/glib-2.0 -I /usr/lib/glib-2.0/include

dupfind: dupfind.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o dupfind dupfind.c -lglib-2.0 -lgcrypt
