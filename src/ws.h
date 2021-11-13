#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHA1HashSize 20
#define UTF8_ACCEPT 0
#define UTF8_REJECT 1
#define MAX_CLIENTS 8
#define MAX_PORTS 16
#define MESSAGE_LENGTH 2048
#define MAX_FRAME_LENGTH (16 * 1024 * 1024)
#define WS_KEY_LEN 24
#define WS_MS_LEN 36
#define WS_KEYMS_LEN (WS_KEY_LEN + WS_MS_LEN)
#define MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_HS_REQ "Sec-WebSocket-Key"
#define WS_HS_ACCLEN 130
#define WS_HS_ACCEPT                        \
	"HTTP/1.1 101 Switching Protocols\r\n" \
	"Upgrade: websocket\r\n"               \
	"Connection: Upgrade\r\n"              \
	"Sec-WebSocket-Accept: "
#define WS_FIN 128
#define WS_FIN_SHIFT 7
#define WS_FR_OP_CONT 0
#define WS_FR_OP_TXT 1
#define WS_FR_OP_BIN 2
#define WS_FR_OP_CLSE 8
#define WS_FR_OP_PING 0x9
#define WS_FR_OP_PONG 0xA
#define WS_FR_OP_UNSUPPORTED 0xF
#define WS_CLSE_NORMAL 1000
#define WS_CLSE_PROTERR 1002
#define WS_CLSE_INVUTF8 1007
#define WS_STATE_CONNECTING 0
#define WS_STATE_OPEN 1
#define WS_STATE_CLOSING 2
#define WS_STATE_CLOSED 3
#define MS_TO_NS(x) ((x)*1000000)
#define TIMEOUT_MS (500)
#define DEBUG(...)
#define CLI_SOCK(sock) (sock)
#define SEND(fd, buf, len) send_all((fd), (buf), (len), MSG_NOSIGNAL)
#define RECV(fd, buf, len) recv((fd), (buf), (len), 0)

enum
{
	shaSuccess = 0,
	shaNull,
	shaInputTooLong,
	shaStateError
};

typedef struct SHA1Context
{
	uint32_t Intermediate_Hash[SHA1HashSize / 4];
	uint32_t Length_Low;
	uint32_t Length_High;
	int_least16_t Message_Block_Index;
	uint8_t Message_Block[64];
	int Computed;
	int Corrupted;
} SHA1Context;

struct ws_events
{

	void (*onopen)(int);

	void (*onclose)(int);

	void (*onmessage)(int, const unsigned char *, uint64_t, int);
};

unsigned char *base64_encode(const unsigned char *src, size_t len, size_t *out_len);
unsigned char *base64_decode(const unsigned char *src, size_t len, size_t *out_len);
int SHA1Reset(SHA1Context *);
int SHA1Input(SHA1Context *, const uint8_t *, unsigned int);
int SHA1Result(SHA1Context *, uint8_t Message_Digest[SHA1HashSize]);
extern int is_utf8(uint8_t *s);
extern int is_utf8_len(uint8_t *s, size_t len);
extern uint32_t is_utf8_len_state(uint8_t *s, size_t len, uint32_t state);
extern int get_handshake_accept(char *wsKey, unsigned char **dest);
extern int get_handshake_response(char *hsrequest, char **hsresponse);
extern char *ws_getaddress(int fd);
extern int ws_sendframe(int fd, const char *msg, uint64_t size, bool broadcast, int type);
extern int ws_sendframe_txt(int fd, const char *msg, bool broadcast);
extern int ws_sendframe_bin(int fd, const char *msg, uint64_t size, bool broadcast);
extern int ws_get_state(int fd);
extern int ws_close_client(int fd);
extern int ws_socket(struct ws_events *evs, uint16_t port, int thread_loop);