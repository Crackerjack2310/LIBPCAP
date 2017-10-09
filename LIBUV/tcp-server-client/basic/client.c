#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

uv_loop_t *loop;
void on_close(uv_handle_t* handle);
void on_connect(uv_connect_t* req, int status);
void on_write(uv_write_t* req, int status);

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	printf("%s : Begin\n", __func__);
	buf->base = (char*) malloc(suggested_size);
	buf->len = suggested_size;
	printf("%s : End\n", __func__);
}

void on_close(uv_handle_t* handle)
{
	printf("%s : Begin\n", __func__);
	printf("closed.");
	printf("%s : End\n", __func__);
}

void on_write(uv_write_t* req, int status)
{
	printf("%s : Begin\n", __func__);
	if (status) {
		fprintf(stderr, "uv_write error: %s\n", uv_strerror(status));
		return;
	}
	printf("wrote.\n");
	//uv_close((uv_handle_t*)req->handle, on_close);
	printf("%s : End\n", __func__);
}

void on_read(uv_stream_t* tcp, ssize_t nread, const struct uv_buf_t *buf)
{
	printf("%s : Begin\n", __func__);
	if(nread >= 0) {
	//	printf("read: %s\n", (char*)tcp->data);
		printf("read: %s\n", buf->base);
	}
	else {
		//we got an EOF
		uv_close((uv_handle_t*)tcp, on_close);
	}

	//cargo-culted
	free(buf->base);
	printf("%s : End\n", __func__);
}

void on_connect(uv_connect_t* connection, int status)
{
	printf("%s : Begin\n", __func__);
	if (status) {
		fprintf(stderr, "on_connect error: %s\n", uv_strerror(status));
		return;
	}	
	printf("connected.\n");
	uv_stream_t* stream = connection->handle;
	uv_buf_t buffer = {"hello World !!!", strlen(buffer.base)};
		//{.base = "world", .len = 5}
	uv_write_t request;
	uv_write(&request, stream, &buffer, 1, on_write);		// this func writes, then on_write is called for checking status
	printf("After write before read_start\n");
	uv_read_start(stream, alloc_cb, on_read);
	printf("%s : End\n", __func__);
}

int main()
{
	printf("%s : Begin\n", __func__);
	loop = uv_default_loop();
	uv_tcp_t* socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(loop, socket);

	uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));

	struct sockaddr_in dest;
	uv_ip4_addr("172.16.1.9", 7000, &dest);			// mention the ip address of the server to target

	uv_tcp_connect(connect, socket, (const struct sockaddr*)&dest, on_connect);
	printf("after tcp_connect...now running uv_loop\n");
	uv_run(loop, UV_RUN_DEFAULT);		
	return 0;
}

