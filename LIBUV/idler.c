#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

int64_t counter = 0;

void wait_for_a_while(uv_idle_t* handle) 
{
	counter++;
	printf("%ld", counter);
	if (counter >= 1000000)
		uv_idle_stop(handle);
}

int main()
{
	uv_loop_t *loop = malloc(sizeof(uv_loop_t));
	if (!loop)
	{
		perror("NUll");
		exit(0);
	}
	uv_loop_init(loop);				// initialize with uv_loop_t structure
	uv_idle_t idler;				// this is a handle
	uv_idle_init(loop, &idler);			// initialize the handler...
    	printf("Idling...\n");			 
    	uv_idle_start(&idler, wait_for_a_while);	// start the handle with given callback	
    	uv_run(loop, UV_RUN_DEFAULT); 			// now begins the wait_for_a_while()
    	uv_loop_close(loop);				// callback shall no longer be called
	free(loop);					
    	return 0;
}
