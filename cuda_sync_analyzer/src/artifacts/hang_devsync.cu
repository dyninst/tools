#include <cuda.h>
#include <cuda_runtime.h>

__global__ void 
VecAdd( int* A) {
	while(1) {
		A[0] = 0;
	}
}

int
main(int argc, char *argv[]) {
	int *d_A;
	cudaMalloc((void**)&d_A, 4096);
	VecAdd<<<1, 1, 0>>>(d_A);
	cudaDeviceSynchronize();
}
