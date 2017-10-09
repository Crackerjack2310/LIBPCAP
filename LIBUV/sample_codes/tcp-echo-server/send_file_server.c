#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

uv_loop_t *loop;
struct sockaddr_in addr;

typedef struct {
	uv_write_t req;
	uv_buf_t buf;
} write_req_t;

uv_loop_t *loop;
uv_pipe_t stdin_pipe;
uv_pipe_t stdout_pipe;
uv_pipe_t file_pipe;

void free_write_req(uv_write_t *req); 
void on_file_write(uv_write_t *req, int status)
{
	printf("%s : begin\n", __func__);
	free_write_req(req);
	printf("%s : end\n", __func__);
}

void free_write_req(uv_write_t *req)
{
	printf("%s : begin\n", __func__);
	write_req_t *wr = (write_req_t*) req;
	free(wr->buf.base);
	free(wr);
	printf("%s : end\n", __func__);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	printf("%s : begin\n", __func__);
	buf->base = (char*) malloc(suggested_size);
	buf->len = suggested_size;
	printf("%s : end\n", __func__);
}

void on_close(uv_handle_t* handle) {
	printf("%s : begin\n", __func__);
	free(handle);
	printf("%s : end\n", __func__);
}

void echo_write(uv_write_t *req, int status) {
	printf("%s : begin\n", __func__);
	if (status) {
		fprintf(stderr, "Write error %s\n", uv_strerror(status));
		return;
	}
	free_write_req(req);
	printf("%s : end\n", __func__);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
	printf("%s : begin\n", __func__);
	if (nread > 0) 
	{
		write_req_t *req = (write_req_t*) malloc(sizeof(write_req_t));
		req->buf = uv_buf_init(buf->base, nread);
		//write_data((uv_stream_t *)&file_pipe, nread, *buf, NULL);
		printf("read: %s\n", buf->base);
		printf("total length: %ld\n", strlen(buf->base));
		//memcpy(req->buf.base, buf.base, size);
		uv_write((uv_write_t*) req, (uv_stream_t*) &file_pipe, &req->buf, 1, echo_write);
		uv_write((uv_write_t*) req, (uv_stream_t*) client, &req->buf, 1, NULL);
		uv_stop(loop);
		return;
	}
	if (nread < 0)
	{
		if (nread != UV_EOF)
			fprintf(stderr, "Read error %s\n", uv_err_name(nread));
		uv_close((uv_handle_t*) client, on_close);
	}
	free(buf->base);
	printf("%s : end\n", __func__);
}

void on_new_connection(uv_stream_t *server, int status)
{
	printf("%s : begin\n", __func__);
	if (status < 0)
	{
		fprintf(stderr, "New connection error %s\n", uv_strerror(status));
		// error!
		return;
	}
	printf("Connection Successful. Client Active !!\n");
	uv_tcp_t *client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
	uv_tcp_init(loop, client);
	if (uv_accept(server, (uv_stream_t*) client) == 0)
	{
		uv_read_start((uv_stream_t*) client, alloc_buffer, echo_read);
	}
	else
	{
		uv_close((uv_handle_t*) client, on_close);
	}
	printf("%s : end\n", __func__);
}
/*
void write_data(uv_stream_t *dest, size_t size, uv_buf_t buf, uv_write_cb cb)
{
	printf("%s : begin\n", __func__);
	write_req_t *req = (write_req_t*) malloc(sizeof(write_req_t));
	req->buf = uv_buf_init((char*) malloc(size), size);
	memcpy(req->buf.base, buf.base, size);
	uv_write((uv_write_t*) req, (uv_stream_t*)dest, &req->buf, 1, cb);
	printf("%s : end\n", __func__);
}

  void read_stdin(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  printf("%s : begin\n", __func__);

  if (nread < 0)
  if (nread == UV_EOF)
  uv_close((uv_handle_t *)&file_pipe, NULL);
  else if (nread > 0) 
  write_data((uv_stream_t *)&file_pipe, nread, *buf, on_file_write);
  if (buf->base)
  free(buf->base);

  printf("%s : end\n", __func__);
  }*/

int main(int argc, char **argv)
{
	printf("%s : begin\n", __func__);
	loop = uv_default_loop();
	uv_tcp_t server;
	uv_tcp_init(loop, &server);
	uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &addr);
	uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
	int r = uv_listen((uv_stream_t*) &server, DEFAULT_BACKLOG, on_new_connection);
	if (r)
	{
		fprintf(stderr, "Listen error %s\n", uv_strerror(r));
		return 1;
	}
	uv_fs_t file_req;
	int fd = uv_fs_open(loop, &file_req, argv[1], O_CREAT | O_RDWR, 0644, NULL);
	uv_pipe_init(loop, &file_pipe, 0);
	uv_pipe_open(&file_pipe, fd);
	uv_run(loop, UV_RUN_DEFAULT);

//////////////////////////////////////////////////////////////// fs_control

	/*	uv_pipe_init(loop, &stdin_pipe, 0);
		uv_pipe_open(&stdin_pipe, 0);

		uv_pipe_init(loop, &stdout_pipe, 0);
		uv_pipe_open(&stdout_pipe, 1);

		uv_fs_t file_req;
		int fd = uv_fs_open(loop, &file_req, argv[1], O_CREAT | O_RDWR, 0644, NULL);
		uv_pipe_init(loop, &file_pipe, 0);
		uv_pipe_open(&file_pipe, fd);

		printf("before read_start\n");
		uv_read_start((uv_stream_t*)&stdin_pipe, alloc_buffer, read_stdin);
		printf("after read_start now run will be called\n");
		uv_run(loop, UV_RUN_DEFAULT);
		printf("after run\n");
	 */
	return 0;
}
