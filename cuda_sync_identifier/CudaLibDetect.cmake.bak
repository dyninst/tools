## 
# Find the specific CUDA libraries that we are interested in

if (DEFINED CRAY_MACHINE AND NOT DEFINED LIBCUDA_SO AND NOT DEFINED LIBCUDART_SO) 
	set(LIBCUDART_SO "$ENV{CRAY_CUDATOOLKIT_DIR}/lib64/libcudart.so")
	set(LIBCUDA_SO "/opt/cray/nvidia/default/lib64/libcuda.so.1")
endif(DEFINED CRAY_MACHINE AND NOT DEFINED LIBCUDA_SO AND NOT DEFINED LIBCUDART_SO)

if (NOT DEFINED LIBCUDA_SO)
	message(ERROR " Set -DLIBCUDA_SO= to the libcuda.so file in use by the system")
endif(NOT DEFINED LIBCUDA_SO)

if (NOT DEFINED LIBCUDART_SO)
	message(ERROR " Set -DLIBCUDART_SO= to the libcudart.so file in use by the system")
endif(NOT DEFINED LIBCUDART_SO)