#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

void on_fs_read(uv_fs_t *req);
uv_fs_t open_req;
uv_fs_t read_req;
uv_buf_t iov;
unsigned char temp[100000];

uv_loop_t *loop, *loop2;;
uv_buf_t buffer;

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
	printf("%s : End\n", __func__);
}

void on_read(uv_stream_t* tcp, ssize_t nread, const struct uv_buf_t *buf)
{
	printf("%s : Begin\n", __func__);
	if(nread >= 0)
		printf("read: %s\n", buf->base);
	else
		uv_close((uv_handle_t*)tcp, on_close);
	free(buf->base);
	uv_stop(loop);
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
	//uv_buf_t buffer = {"hello World !!!", strlen(buffer.base)};
	uv_write_t request;
	uv_write(&request, stream, &buffer, 1, on_write);		// this func writes, then on_write is called for checking status
	printf("After write before read_start\n");
	uv_read_start(stream, alloc_cb, on_read);
	printf("%s : End\n", __func__);
}
void on_fs_read(uv_fs_t *req)
{
	printf("%s : Begin\n", __func__);
	if (req->result < 0) 
		fprintf(stderr, "Read error: %s\n", uv_strerror(req->result));
	else if (req->result == 0) 
	{
		uv_fs_t close_req;
		uv_fs_close(uv_default_loop(), &close_req, open_req.result, NULL);
	}
	else if (req->result > 0)
	{
		iov.len = req->result;
//		uv_fs_write(uv_default_loop(), &write_req, 1, &iov, 1, -1, on_write);
	}
	buffer.base = temp;
	buffer.len = strlen(temp);
	//printf("iov value : %s\n", iov.base);
	//printf("buffer in on_read : %s\n", buffer);
	printf("%s : End\n", __func__);
}

void on_open(uv_fs_t *req)
{
	printf("%s : Begin\n", __func__);
	// The request passed to the callback is the same as the one the call setup
	// function was passed.
	assert(req == &open_req);
	if (req->result >= 0) 
	{
		iov = uv_buf_init(temp, sizeof(temp));
		//      printf("req->result : %ld\n", req->result);
		uv_fs_read(loop, &read_req, req->result, &iov, 1, -1, on_fs_read);
	}
	else
	{
		fprintf(stderr, "error opening file: %s\n", uv_strerror((int)req->result));
	}
//	printf("iov value in on_open : %s\n", iov.base);
//	printf("buffer in on_open : %s\n", buffer);
	printf("%s : End\n", __func__);
}

int main(int argc, char **argv)
{
	printf("%s : Begin\n", __func__);
	loop = uv_default_loop();
	uv_fs_open(loop, &open_req, argv[1], O_RDONLY, 0, on_open);
	//loop2 = malloc(sizeof(uv_loop_t));

	uv_run(loop, UV_RUN_DEFAULT);		
	
	uv_tcp_t* socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(loop, socket);

	uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));

	struct sockaddr_in dest;
	uv_ip4_addr("172.16.1.8", 9000, &dest);			// mention the ip address of the server to target

	uv_tcp_connect(connect, socket, (const struct sockaddr*)&dest, on_connect);
	printf("after tcp_connect...now running uv_loop\n");
	uv_run(loop, UV_RUN_DEFAULT);		
	//uv_run(uv_default_loop(), UV_RUN_DEFAULT);

	uv_fs_req_cleanup(&open_req);
	uv_fs_req_cleanup(&read_req);

	return 0;
}
