#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef int socklen_t;
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#include <unistd.h>

#include "ws.h"

#define SHA1CircularShift(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const uint8_t utf8d[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 00..1f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20..3f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 40..5f
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 60..7f
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, // 80..9f
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // a0..bf
    8, 8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // c0..df
    0xa, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x4, 0x3, 0x3,				// e0..ef
    0xb, 0x6, 0x6, 0x6, 0x5, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8,				// f0..ff
    0x0, 0x1, 0x2, 0x3, 0x5, 0x8, 0x7, 0x1, 0x1, 0x1, 0x4, 0x6, 0x1, 0x1, 0x1, 0x1,				// s0..s0
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, // s1..s2
    1, 2, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, // s3..s4
    1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1, // s5..s6
    1, 3, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // s7..s8
};

int port_index;

struct ws_port
{
	int port_number;
	struct ws_events events;
};

struct ws_accept
{
	int sock;
	int port_index;
};

struct ws_port ports[MAX_PORTS];

struct ws_connection
{
	int client_sock;
	int port_index;
	int state;

	pthread_mutex_t mtx_state;
	pthread_cond_t cnd_state_close;
	pthread_t thrd_tout;
	bool close_thrd;
};

struct ws_connection client_socks[MAX_CLIENTS];

struct ws_frame_data
{

	unsigned char frm[MESSAGE_LENGTH];

	unsigned char *msg;

	unsigned char msg_ctrl[125];

	size_t cur_pos;

	size_t amt_read;

	int frame_type;

	uint64_t frame_size;

	int error;

	int sock;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

#define panic(s)     \
	do              \
	{               \
		perror(s); \
		exit(-1);  \
	} while (0);

void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

unsigned char *base64_encode(const unsigned char *src, size_t len, size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4;
	olen += olen / 72;
	olen++;
	if (olen < len)
		return NULL;
	out = malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3)
	{
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72)
		{
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in)
	{
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1)
		{
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		}
		else
		{
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
							  (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}

unsigned char *base64_decode(const unsigned char *src, size_t len,
					    size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char)i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++)
	{
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++)
	{
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4)
		{
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad)
			{
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else
				{
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}

int get_handshake_accept(char *wsKey, unsigned char **dest)
{
	unsigned char hash[SHA1HashSize];
	SHA1Context ctx;
	char *str;

	if (!wsKey)
		return (-1);

	str = calloc(1, sizeof(char) * (WS_KEY_LEN + WS_MS_LEN + 1));
	if (!str)
		return (-1);

	strncpy(str, wsKey, WS_KEY_LEN);
	strcat(str, MAGIC_STRING);

	SHA1Reset(&ctx);
	SHA1Input(&ctx, (const uint8_t *)str, WS_KEYMS_LEN);
	SHA1Result(&ctx, hash);

	*dest = base64_encode(hash, SHA1HashSize, NULL);
	*(*dest + strlen((const char *)*dest) - 1) = '\0';
	free(str);
	return (0);
}

int get_handshake_response(char *hsrequest, char **hsresponse)
{
	unsigned char *accept;
	char *saveptr;
	char *s;
	int ret;

	saveptr = NULL;
	for (s = strtok_r(hsrequest, "\r\n", &saveptr); s != NULL;
		s = strtok_r(NULL, "\r\n", &saveptr))
	{
		if (strstr(s, WS_HS_REQ) != NULL)
			break;
	}

	if (s == NULL)
		return (-1);

	saveptr = NULL;
	s = strtok_r(s, " ", &saveptr);
	s = strtok_r(NULL, " ", &saveptr);

	ret = get_handshake_accept(s, &accept);
	if (ret < 0)
		return (ret);

	*hsresponse = malloc(sizeof(char) * WS_HS_ACCLEN);
	if (*hsresponse == NULL)
		return (-1);

	strcpy(*hsresponse, WS_HS_ACCEPT);
	strcat(*hsresponse, (const char *)accept);
	strcat(*hsresponse, "\r\n\r\n");

	free(accept);
	return (0);
}

int SHA1Reset(SHA1Context *context)
{
	if (!context)
	{
		return shaNull;
	}

	context->Length_Low = 0;
	context->Length_High = 0;
	context->Message_Block_Index = 0;

	context->Intermediate_Hash[0] = 0x67452301;
	context->Intermediate_Hash[1] = 0xEFCDAB89;
	context->Intermediate_Hash[2] = 0x98BADCFE;
	context->Intermediate_Hash[3] = 0x10325476;
	context->Intermediate_Hash[4] = 0xC3D2E1F0;

	context->Computed = 0;
	context->Corrupted = 0;

	return shaSuccess;
}

int SHA1Result(SHA1Context *context,
			uint8_t Message_Digest[SHA1HashSize])
{
	int i;

	if (!context || !Message_Digest)
	{
		return shaNull;
	}

	if (context->Corrupted)
	{
		return context->Corrupted;
	}

	if (!context->Computed)
	{
		SHA1PadMessage(context);
		for (i = 0; i < 64; ++i)
		{
			context->Message_Block[i] = 0;
		}
		context->Length_Low = 0;
		context->Length_High = 0;
		context->Computed = 1;
	}

	for (i = 0; i < SHA1HashSize; ++i)
	{
		Message_Digest[i] = context->Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03));
	}

	return shaSuccess;
}

int SHA1Input(SHA1Context *context,
		    const uint8_t *message_array,
		    unsigned length)
{
	if (!length)
	{
		return shaSuccess;
	}

	if (!context || !message_array)
	{
		return shaNull;
	}

	if (context->Computed)
	{
		context->Corrupted = shaStateError;

		return shaStateError;
	}

	if (context->Corrupted)
	{
		return context->Corrupted;
	}
	while (length-- && !context->Corrupted)
	{
		context->Message_Block[context->Message_Block_Index++] =
		    (*message_array & 0xFF);

		context->Length_Low += 8;
		if (context->Length_Low == 0)
		{
			context->Length_High++;
			if (context->Length_High == 0)
			{
				context->Corrupted = 1;
			}
		}

		if (context->Message_Block_Index == 64)
		{
			SHA1ProcessMessageBlock(context);
		}

		message_array++;
	}

	return shaSuccess;
}

void SHA1ProcessMessageBlock(SHA1Context *context)
{
	const uint32_t K[] = {
	    0x5A827999,
	    0x6ED9EBA1,
	    0x8F1BBCDC,
	    0xCA62C1D6};
	int t;
	uint32_t temp;
	uint32_t W[80];
	uint32_t A, B, C, D, E;

	for (t = 0; t < 16; t++)
	{
		W[t] = context->Message_Block[t * 4] << 24;
		W[t] |= context->Message_Block[t * 4 + 1] << 16;
		W[t] |= context->Message_Block[t * 4 + 2] << 8;
		W[t] |= context->Message_Block[t * 4 + 3];
	}

	for (t = 16; t < 80; t++)
	{
		W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}

	A = context->Intermediate_Hash[0];
	B = context->Intermediate_Hash[1];
	C = context->Intermediate_Hash[2];
	D = context->Intermediate_Hash[3];
	E = context->Intermediate_Hash[4];

	for (t = 0; t < 20; t++)
	{
		temp = SHA1CircularShift(5, A) +
			  ((B & C) | ((~B) & D)) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);

		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++)
	{
		temp = SHA1CircularShift(5, A) +
			  ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;

	context->Message_Block_Index = 0;
}

void SHA1PadMessage(SHA1Context *context)
{
	if (context->Message_Block_Index > 55)
	{
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 64)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}

		SHA1ProcessMessageBlock(context);

		while (context->Message_Block_Index < 56)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}
	else
	{
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 56)
		{

			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}

	context->Message_Block[56] = context->Length_High >> 24;
	context->Message_Block[57] = context->Length_High >> 16;
	context->Message_Block[58] = context->Length_High >> 8;
	context->Message_Block[59] = context->Length_High;
	context->Message_Block[60] = context->Length_Low >> 24;
	context->Message_Block[61] = context->Length_Low >> 16;
	context->Message_Block[62] = context->Length_Low >> 8;
	context->Message_Block[63] = context->Length_Low;

	SHA1ProcessMessageBlock(context);
}

static uint32_t decode(uint32_t *state, uint32_t *codep, uint32_t byte)
{
	uint32_t type = utf8d[byte];

	*codep = (*state != UTF8_ACCEPT) ? (byte & 0x3fu) | (*codep << 6) : (0xff >> type) & (byte);

	*state = utf8d[256 + *state * 16 + type];
	return *state;
}

int is_utf8(uint8_t *s)
{
	uint32_t codepoint, state = 0;

	while (*s)
		decode(&state, &codepoint, *s++);

	return state == UTF8_ACCEPT;
}

int is_utf8_len(uint8_t *s, size_t len)
{
	uint32_t codepoint, state = 0;
	size_t i;

	for (i = 0; i < len; i++)
		decode(&state, &codepoint, *s++);

	return state == UTF8_ACCEPT;
}

uint32_t is_utf8_len_state(uint8_t *s, size_t len, uint32_t state)
{
	uint32_t codepoint;
	size_t i;

	for (i = 0; i < len; i++)
		decode(&state, &codepoint, *s++);

	return state;
}

static void close_socket(int fd)
{
#ifndef _WIN32
	shutdown(fd, SHUT_RDWR);
	close(fd);
#else
	closesocket(fd);
#endif
}

static ssize_t send_all(int sockfd, const void *buf, size_t len, int flags)
{
	const char *p;
	ssize_t ret;
	p = buf;
	while (len)
	{
		ret = send(sockfd, p, len, flags);
		if (ret == -1)
			return (-1);
		p += ret;
		len -= ret;
	}
	return (0);
}

static int get_client_index(int fd)
{
	int i;
	pthread_mutex_lock(&mutex);
	for (i = 0; i < MAX_CLIENTS; i++)
		if (client_socks[i].client_sock == fd)
			break;
	pthread_mutex_unlock(&mutex);
	return (i == MAX_CLIENTS ? -1 : i);
}

static int get_client_state(int idx)
{
	int state;

	if (idx < 0 || idx >= MAX_CLIENTS)
		return (-1);

	pthread_mutex_lock(&client_socks[idx].mtx_state);
	state = client_socks[idx].state;
	pthread_mutex_unlock(&client_socks[idx].mtx_state);
	return (state);
}

static int set_client_state(int idx, int state)
{
	if (idx < 0 || idx >= MAX_CLIENTS)
		return (-1);

	if (state < 0 || state > 3)
		return (-1);

	pthread_mutex_lock(&client_socks[idx].mtx_state);
	client_socks[idx].state = state;
	pthread_mutex_unlock(&client_socks[idx].mtx_state);
	return (0);
}

static void *close_timeout(void *p)
{
	struct ws_connection *conn = p;
	struct timespec ts;

	pthread_mutex_lock(&conn->mtx_state);

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_nsec += MS_TO_NS(TIMEOUT_MS);

	while (ts.tv_nsec >= 1000000000)
	{
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}

	while (conn->state != WS_STATE_CLOSED &&
		  pthread_cond_timedwait(&conn->cnd_state_close, &conn->mtx_state, &ts) !=
			 ETIMEDOUT)
		;

	if (conn->state == WS_STATE_CLOSED)
		goto quit;

	DEBUG("Timer expired, closing client %d\n", conn->client_sock);

	close_socket(conn->client_sock);
	conn->client_sock = -1;
	conn->state = WS_STATE_CLOSED;
quit:
	pthread_mutex_unlock(&conn->mtx_state);
	return (NULL);
}

static int start_close_timeout(int idx)
{
	if (idx < 0 || idx >= MAX_CLIENTS)
		return (-1);

	pthread_mutex_lock(&client_socks[idx].mtx_state);

	if (client_socks[idx].state != WS_STATE_OPEN)
		goto out;

	client_socks[idx].state = WS_STATE_CLOSING;

	if (pthread_create(
		   &client_socks[idx].thrd_tout, NULL, close_timeout, &client_socks[idx]))
	{
		pthread_mutex_unlock(&client_socks[idx].mtx_state);
		panic("Unable to create timeout thread\n");
	}
	client_socks[idx].close_thrd = true;
out:
	pthread_mutex_unlock(&client_socks[idx].mtx_state);
	return (0);
}

char *ws_getaddress(int fd)
{
	struct sockaddr_in addr;
	socklen_t addr_size;
	char *client;

	addr_size = sizeof(struct sockaddr_in);
	if (getpeername(fd, (struct sockaddr *)&addr, &addr_size) < 0)
		return (NULL);

	client = malloc(sizeof(char) * INET_ADDRSTRLEN);
	if (!client)
		return (NULL);

	if (!inet_ntop(AF_INET, &addr.sin_addr, client, INET_ADDRSTRLEN))
	{
		free(client);
		return (NULL);
	}
	return (client);
}

int ws_sendframe(int fd, const char *msg, uint64_t size, bool broadcast, int type)
{
	unsigned char *response;
	unsigned char frame[10];
	uint8_t idx_first_rData;
	uint64_t length;
	int idx_response;
	ssize_t output;
	ssize_t send_ret;
	int sock;
	uint64_t i;
	int cur_port_index;

	frame[0] = (WS_FIN | type);
	length = (uint64_t)size;

	if (length <= 125)
	{
		frame[1] = length & 0x7F;
		idx_first_rData = 2;
	}

	else if (length >= 126 && length <= 65535)
	{
		frame[1] = 126;
		frame[2] = (length >> 8) & 255;
		frame[3] = length & 255;
		idx_first_rData = 4;
	}

	else
	{
		frame[1] = 127;
		frame[2] = (unsigned char)((length >> 56) & 255);
		frame[3] = (unsigned char)((length >> 48) & 255);
		frame[4] = (unsigned char)((length >> 40) & 255);
		frame[5] = (unsigned char)((length >> 32) & 255);
		frame[6] = (unsigned char)((length >> 24) & 255);
		frame[7] = (unsigned char)((length >> 16) & 255);
		frame[8] = (unsigned char)((length >> 8) & 255);
		frame[9] = (unsigned char)(length & 255);
		idx_first_rData = 10;
	}

	idx_response = 0;
	response = malloc(sizeof(unsigned char) * (idx_first_rData + length + 1));
	if (!response)
		return (-1);

	for (i = 0; i < idx_first_rData; i++)
	{
		response[i] = frame[i];
		idx_response++;
	}

	for (i = 0; i < length; i++)
	{
		response[idx_response] = msg[i];
		idx_response++;
	}

	response[idx_response] = '\0';
	output = SEND(fd, response, idx_response);

	if (output != -1 && broadcast)
	{
		pthread_mutex_lock(&mutex);
		cur_port_index = -1;
		for (i = 0; i < MAX_CLIENTS; i++)
			if (client_socks[i].client_sock == fd)
				cur_port_index = client_socks[i].port_index, i = MAX_CLIENTS;

		for (i = 0; i < MAX_CLIENTS; i++)
		{
			sock = client_socks[i].client_sock;
			if ((sock > -1) && (sock != fd) &&
			    (client_socks[i].port_index == cur_port_index))
			{
				if ((send_ret = SEND(sock, response, idx_response)) != -1)
					output += send_ret;
				else
				{
					output = -1;
					break;
				}
			}
		}
		pthread_mutex_unlock(&mutex);
	}

	free(response);
	return ((int)output);
}

int ws_sendframe_txt(int fd, const char *msg, bool broadcast)
{
	return ws_sendframe(fd, msg, (uint64_t)strlen(msg), broadcast, WS_FR_OP_TXT);
}

int ws_sendframe_bin(int fd, const char *msg, uint64_t size, bool broadcast)
{
	return ws_sendframe(fd, msg, size, broadcast, WS_FR_OP_BIN);
}

int ws_get_state(int fd)
{
	int idx;

	if ((idx = get_client_index(fd)) == -1)
		return (-1);

	return (get_client_state(idx));
}

int ws_close_client(int fd)
{
	unsigned char clse_code[2];
	int cc;
	int i;

	if ((i = get_client_index(fd)) == -1)
		return (-1);

	cc = WS_CLSE_NORMAL;
	clse_code[0] = (cc >> 8);
	clse_code[1] = (cc & 0xFF);
	if (ws_sendframe(CLI_SOCK(fd), (const char *)clse_code, sizeof(char) * 2, false,
				  WS_FR_OP_CLSE) < 0)
	{
		DEBUG("An error has occurred while sending closing frame!\n");
		return (-1);
	}

	start_close_timeout(i);
	return (0);
}

static inline int is_control_frame(int frame)
{
	return (
	    frame == WS_FR_OP_CLSE || frame == WS_FR_OP_PING || frame == WS_FR_OP_PONG);
}

static int do_handshake(struct ws_frame_data *wfd, int p_index)
{
	char *response;
	char *p;
	ssize_t n;

	if ((n = RECV(wfd->sock, wfd->frm, sizeof(wfd->frm) - 1)) < 0)
		return (-1);

	p = strstr((const char *)wfd->frm, "\r\n\r\n");
	if (p == NULL)
	{
		DEBUG("An empty line with \\r\\n was expected!\n");
		return (-1);
	}
	wfd->amt_read = n;
	wfd->cur_pos = (size_t)((ptrdiff_t)(p - (char *)wfd->frm)) + 4;

	if (get_handshake_response((char *)wfd->frm, &response) < 0)
	{
		DEBUG("Cannot get handshake response, request was: %s\n", wfd->frm);
		return (-1);
	}

	DEBUG("Handshaked, response: \n"
		 "------------------------------------\n"
		 "%s"
		 "------------------------------------\n",
		 response);

	if (SEND(wfd->sock, response, strlen(response)) < 0)
	{
		free(response);
		DEBUG("As error has occurred while handshaking!\n");
		return (-1);
	}

	ports[p_index].events.onopen(CLI_SOCK(wfd->sock));
	free(response);
	return (0);
}

static int do_close(struct ws_frame_data *wfd, int close_code)
{
	int cc;

	if (close_code != -1)
	{
		cc = close_code;
		goto custom_close;
	}

	if (wfd->frame_size == 0 || wfd->frame_size > 2)
		goto send;

	if (wfd->frame_size == 1)
		cc = wfd->msg_ctrl[0];
	else
		cc = ((int)wfd->msg_ctrl[0]) << 8 | wfd->msg_ctrl[1];

	if ((cc < 1000 || cc > 1003) && (cc < 1007 || cc > 1011) &&
	    (cc < 3000 || cc > 4999))
	{
		cc = WS_CLSE_PROTERR;

	custom_close:
		wfd->msg_ctrl[0] = (cc >> 8);
		wfd->msg_ctrl[1] = (cc & 0xFF);

		if (ws_sendframe(CLI_SOCK(wfd->sock), (const char *)wfd->msg_ctrl,
					  sizeof(char) * 2, false, WS_FR_OP_CLSE) < 0)
		{
			DEBUG("An error has occurred while sending closing frame!\n");
			return (-1);
		}
		return (0);
	}

send:
	if (ws_sendframe(CLI_SOCK(wfd->sock), (const char *)wfd->msg_ctrl,
				  wfd->frame_size, false, WS_FR_OP_CLSE) < 0)
	{
		DEBUG("An error has occurred while sending closing frame!\n");
		return (-1);
	}
	return (0);
}

static int do_pong(struct ws_frame_data *wfd, uint64_t frame_size)
{
	if (ws_sendframe(CLI_SOCK(wfd->sock), (const char *)wfd->msg_ctrl, frame_size,
				  false, WS_FR_OP_PONG) < 0)
	{
		wfd->error = 1;
		DEBUG("An error has occurred while ponging!\n");
		return (-1);
	}
	return (0);
}

static inline int next_byte(struct ws_frame_data *wfd)
{
	ssize_t n;

	if (wfd->cur_pos == 0 || wfd->cur_pos == wfd->amt_read)
	{
		if ((n = RECV(wfd->sock, wfd->frm, sizeof(wfd->frm))) <= 0)
		{
			wfd->error = 1;
			DEBUG("An error has occurred while trying to read next byte\n");
			return (-1);
		}
		wfd->amt_read = (size_t)n;
		wfd->cur_pos = 0;
	}
	return (wfd->frm[wfd->cur_pos++]);
}

static int skip_frame(struct ws_frame_data *wfd, uint64_t frame_size)
{
	uint64_t i;
	for (i = 0; i < frame_size; i++)
	{
		if (next_byte(wfd) == -1)
		{
			wfd->error = 1;
			return (-1);
		}
	}
	return (0);
}

static int read_frame(struct ws_frame_data *wfd,
				  int opcode,
				  unsigned char **buf,
				  uint64_t *frame_length,
				  uint64_t *frame_size,
				  uint64_t *msg_idx,
				  uint8_t *masks,
				  int is_fin)
{
	unsigned char *tmp;
	unsigned char *msg;
	int cur_byte;
	uint64_t i;

	msg = *buf;

	if (*frame_length == 126)
		*frame_length = (((uint64_t)next_byte(wfd)) << 8) | next_byte(wfd);

	else if (*frame_length == 127)
	{
		*frame_length =
		    (((uint64_t)next_byte(wfd)) << 56) |
		    (((uint64_t)next_byte(wfd)) << 48) |
		    (((uint64_t)next_byte(wfd)) << 40) | (((uint64_t)next_byte(wfd)) << 32) |
		    (((uint64_t)next_byte(wfd)) << 24) | (((uint64_t)next_byte(wfd)) << 16) |
		    (((uint64_t)next_byte(wfd)) << 8) |
		    (((uint64_t)next_byte(wfd)));
	}

	*frame_size += *frame_length;

	if (*frame_size > MAX_FRAME_LENGTH)
	{
		DEBUG("Current frame from client %d, exceeds the maximum\n"
			 "amount of bytes allowed (%" PRId64 "/%d)!",
			 wfd->sock, *frame_size + *frame_length, MAX_FRAME_LENGTH);

		wfd->error = 1;
		return (-1);
	}

	masks[0] = next_byte(wfd);
	masks[1] = next_byte(wfd);
	masks[2] = next_byte(wfd);
	masks[3] = next_byte(wfd);

	if (wfd->error)
		return (-1);

	if (*frame_length > 0)
	{
		if (!is_control_frame(opcode))
		{
			tmp = realloc(
			    msg, sizeof(unsigned char) * (*msg_idx + *frame_length + is_fin));
			if (!tmp)
			{
				DEBUG("Cannot allocate memory, requested: % " PRId64 "\n",
					 (*msg_idx + *frame_length + is_fin));

				wfd->error = 1;
				return (-1);
			}
			msg = tmp;
			*buf = msg;
		}

		for (i = 0; i < *frame_length; i++, (*msg_idx)++)
		{

			cur_byte = next_byte(wfd);
			if (cur_byte == -1)
				return (-1);

			msg[*msg_idx] = cur_byte ^ masks[i % 4];
		}
	}

	if (is_fin && *frame_size > 0)
	{

		if (!*frame_length && !is_control_frame(opcode))
		{
			tmp = realloc(msg, sizeof(unsigned char) * (*msg_idx + 1));
			if (!tmp)
			{
				DEBUG("Cannot allocate memory, requested: %" PRId64 "\n",
					 (*msg_idx + 1));

				wfd->error = 1;
				return (-1);
			}
			msg = tmp;
			*buf = msg;
		}
		msg[*msg_idx] = '\0';
	}

	return (0);
}

static int next_frame(struct ws_frame_data *wfd, int idx)
{
	unsigned char *msg_data;
	unsigned char *msg_ctrl;
	uint8_t masks_data[4];
	uint8_t masks_ctrl[4];
	uint64_t msg_idx_data;
	uint64_t msg_idx_ctrl;
	uint64_t frame_length;
	uint64_t frame_size;
	uint32_t utf8_state;
	uint8_t opcode;
	uint8_t is_fin;
	uint8_t mask;
	int cur_byte;

	msg_data = NULL;
	msg_ctrl = wfd->msg_ctrl;
	is_fin = 0;
	frame_length = 0;
	frame_size = 0;
	msg_idx_data = 0;
	msg_idx_ctrl = 0;
	wfd->frame_size = 0;
	wfd->frame_type = -1;
	wfd->msg = NULL;
	utf8_state = UTF8_ACCEPT;

	do
	{

		cur_byte = next_byte(wfd);
		if (cur_byte == -1)
			return (-1);

		is_fin = (cur_byte & 0xFF) >> WS_FIN_SHIFT;
		opcode = (cur_byte & 0xF);

		if (cur_byte & 0x70)
		{
			DEBUG("RSV is set while wsServer do not negotiate extensions!\n");
			wfd->error = 1;
			break;
		}

		if ((wfd->frame_type == -1 && opcode == WS_FR_OP_CONT) ||
		    (wfd->frame_type != -1 && !is_control_frame(opcode) &&
			opcode != WS_FR_OP_CONT))
		{
			DEBUG("Unexpected frame was received!, opcode: %d, previous: %d\n",
				 opcode, wfd->frame_type);
			wfd->error = 1;
			break;
		}

		if (opcode == WS_FR_OP_TXT || opcode == WS_FR_OP_BIN ||
		    opcode == WS_FR_OP_CONT || opcode == WS_FR_OP_PING ||
		    opcode == WS_FR_OP_PONG || opcode == WS_FR_OP_CLSE)
		{

			if (get_client_state(idx) == WS_STATE_CLOSING && opcode != WS_FR_OP_CLSE)
			{
				DEBUG(
				    "Unexpected frame received, expected CLOSE (%d), received: (%d)",
				    WS_FR_OP_CLSE, opcode);
				wfd->error = 1;
				break;
			}

			if (opcode != WS_FR_OP_CONT && !is_control_frame(opcode))
				wfd->frame_type = opcode;

			mask = next_byte(wfd);
			frame_length = mask & 0x7F;
			frame_size = 0;
			msg_idx_ctrl = 0;

			if (is_control_frame(opcode) && (!is_fin || frame_length > 125))
			{
				DEBUG("Control frame bigger than 125 octets or not a FIN frame!\n");
				wfd->error = 1;
				break;
			}

			if (opcode == WS_FR_OP_TXT || opcode == WS_FR_OP_BIN ||
			    opcode == WS_FR_OP_CONT)
			{
				read_frame(wfd, opcode, &msg_data, &frame_length, &wfd->frame_size,
						 &msg_idx_data, masks_data, is_fin);

#ifdef VALIDATE_UTF8

				if (wfd->frame_type == WS_FR_OP_TXT)
				{
					if (is_fin)
					{
						if (is_utf8_len_state(
							   msg_data + (msg_idx_data - frame_length),
							   frame_length, utf8_state) != UTF8_ACCEPT)
						{
							DEBUG("Dropping invalid complete message!\n");
							wfd->error = 1;
							do_close(wfd, WS_CLSE_INVUTF8);
						}
					}

					else
					{
						utf8_state = is_utf8_len_state(
						    msg_data + (msg_idx_data - frame_length), frame_length,
						    utf8_state);

						if (utf8_state == UTF8_REJECT)
						{
							DEBUG("Dropping invalid cont/initial frame!\n");
							wfd->error = 1;
							do_close(wfd, WS_CLSE_INVUTF8);
						}
					}
				}
#endif
			}

			else if (opcode == WS_FR_OP_PONG)
			{
				skip_frame(wfd, 4 + frame_length);
				is_fin = 0;
				continue;
			}

			else if (opcode == WS_FR_OP_PING)
			{
				if (read_frame(wfd, opcode, &msg_ctrl, &frame_length, &frame_size,
							&msg_idx_ctrl, masks_ctrl, is_fin) < 0)
					break;

				if (do_pong(wfd, frame_size) < 0)
					break;

				is_fin = 0;
			}

			else
			{
				if (read_frame(wfd, opcode, &msg_ctrl, &frame_length, &frame_size,
							&msg_idx_ctrl, masks_ctrl, is_fin) < 0)
					break;

#ifdef VALIDATE_UTF8

				if (frame_size > 2 && !is_utf8_len(msg_ctrl + 2, frame_size - 2))
				{
					DEBUG("Invalid close frame payload reason! (not UTF-8)\n");
					wfd->error = 1;
					break;
				}
#endif

				wfd->frame_size = frame_size;
				wfd->frame_type = WS_FR_OP_CLSE;
				free(msg_data);
				return (0);
			}
		}

		else
		{
			DEBUG("Unsupported frame opcode: %d\n", opcode);

			wfd->frame_type = opcode;
			wfd->error = 1;
		}

	} while (!is_fin && !wfd->error);

	if (wfd->error)
	{
		free(msg_data);
		wfd->msg = NULL;
		return (-1);
	}

	wfd->msg = msg_data;
	return (0);
}

static void *ws_establishconnection(void *vsock)
{
	struct ws_frame_data wfd;
	int connection_index;
	int clse_thrd;
	int p_index;
	int sock;

	connection_index = (int)(intptr_t)vsock;
	sock = client_socks[connection_index].client_sock;
	p_index = client_socks[connection_index].port_index;

	memset(&wfd, 0, sizeof(wfd));
	wfd.sock = sock;

	if (do_handshake(&wfd, p_index) < 0)
		goto closed;

	set_client_state(connection_index, WS_STATE_OPEN);

	while (next_frame(&wfd, connection_index) >= 0)
	{

		if ((wfd.frame_type == WS_FR_OP_TXT || wfd.frame_type == WS_FR_OP_BIN) &&
		    !wfd.error)
		{
			ports[p_index].events.onmessage(
			    sock, wfd.msg, wfd.frame_size, wfd.frame_type);
		}

		else if (wfd.frame_type == WS_FR_OP_CLSE && !wfd.error)
		{

			if (get_client_state(connection_index) != WS_STATE_CLOSING)
			{
				set_client_state(connection_index, WS_STATE_CLOSING);

				do_close(&wfd, -1);
			}

			free(wfd.msg);
			break;
		}

		free(wfd.msg);
	}

	ports[p_index].events.onclose(sock);

closed:
	pthread_mutex_lock(&client_socks[connection_index].mtx_state);

	clse_thrd = client_socks[connection_index].close_thrd;
	if (client_socks[connection_index].state != WS_STATE_CLOSED)
	{

		client_socks[connection_index].client_sock = -1;
		client_socks[connection_index].state = WS_STATE_CLOSED;
		close_socket(sock);
		pthread_cond_signal(&client_socks[connection_index].cnd_state_close);
	}

	pthread_mutex_unlock(&client_socks[connection_index].mtx_state);

	if (clse_thrd)
		pthread_join(client_socks[connection_index].thrd_tout, NULL);

	pthread_cond_destroy(&client_socks[connection_index].cnd_state_close);
	pthread_mutex_destroy(&client_socks[connection_index].mtx_state);
	client_socks[connection_index].close_thrd = false;
	return (vsock);
}

static void *ws_accept(void *data)
{
	struct ws_accept *accept_data;
	struct sockaddr_in client;
	pthread_t client_thread;
	int connection_index;
	int new_sock;
	int len;
	int i;

	connection_index = 0;
	accept_data = data;
	len = sizeof(struct sockaddr_in);

	while (1)
	{

		new_sock =
		    accept(accept_data->sock, (struct sockaddr *)&client, (socklen_t *)&len);

		if (new_sock < 0)
			panic("Error on accepting connections..");

		pthread_mutex_lock(&mutex);
		for (i = 0; i < MAX_CLIENTS; i++)
		{
			if (client_socks[i].client_sock == -1)
			{
				client_socks[i].client_sock = new_sock;
				client_socks[i].port_index = accept_data->port_index;
				client_socks[i].state = WS_STATE_CONNECTING;
				client_socks[i].close_thrd = false;
				connection_index = i;

				if (pthread_mutex_init(&client_socks[i].mtx_state, NULL))
					panic("Error on allocating close mutex");
				if (pthread_cond_init(&client_socks[i].cnd_state_close, NULL))
					panic("Error on allocating condition var\n");
				break;
			}
		}
		pthread_mutex_unlock(&mutex);

		if (i != MAX_CLIENTS)
		{
			if (pthread_create(&client_thread, NULL, ws_establishconnection,
						    (void *)(intptr_t)connection_index))
				panic("Could not create the client thread!");

			pthread_detach(client_thread);
		}
		else
			close_socket(new_sock);
	}
	free(data);
	return (data);
}

int ws_socket(struct ws_events *evs, uint16_t port, int thread_loop)
{
	struct ws_accept *accept_data;
	struct sockaddr_in server;
	pthread_t accept_thread;
	int reuse;

	if (evs == NULL)
		panic("Invalid event list!");

	accept_data = malloc(sizeof(*accept_data));
	if (!accept_data)
		panic("Cannot allocate accept data, out of memory!\n");

	pthread_mutex_lock(&mutex);
	if (port_index >= MAX_PORTS)
	{
		pthread_mutex_unlock(&mutex);
		panic("too much websocket ports opened !");
	}
	accept_data->port_index = port_index;
	port_index++;
	pthread_mutex_unlock(&mutex);

	memcpy(&ports[accept_data->port_index].events, evs, sizeof(struct ws_events));
	ports[accept_data->port_index].port_number = port;

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		panic("WSAStartup failed!");

	setvbuf(stdout, NULL, _IONBF, 0);
#endif

	accept_data->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (accept_data->sock < 0)
		panic("Could not create socket");

	reuse = 1;
	if (setsockopt(accept_data->sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
				sizeof(reuse)) < 0)
	{
		panic("setsockopt(SO_REUSEADDR) failed");
	}

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(port);

	if (bind(accept_data->sock, (struct sockaddr *)&server, sizeof(server)) < 0)
		panic("Bind failed");

	listen(accept_data->sock, MAX_CLIENTS);

	printf("Waiting for incoming connections...\n");
	memset(client_socks, -1, sizeof(client_socks));

	if (!thread_loop)
		ws_accept(accept_data);
	else
	{
		if (pthread_create(&accept_thread, NULL, ws_accept, accept_data))
			panic("Could not create the client thread!");
		pthread_detach(accept_thread);
	}

	return (0);
}