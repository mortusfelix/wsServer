@rmdir build
@mkdir build 
cc -c src/base64.c -Iinclude -o build/base64.o
cc -c src/handshake.c -Iinclude -o build/handshake.o
cc -c src/sha1.c -Iinclude -o build/sha1.o 
cc -c src/utf8.c -Iinclude -o build/utf8.o 
cc -c src/ws.c -Iinclude -o build/ws.o
cc -c example/server.c -Iinclude -o build/server.o 
cc build/base64.o build/handshake.o build/server.o build/sha1.o build/utf8.o build/ws.o -o build/wsserver.exe -lws2_32 -static