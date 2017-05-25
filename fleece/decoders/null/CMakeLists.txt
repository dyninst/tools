MESSAGE(STATUS "Using decoder: null")

# Set the sources that should be compiled into the library
SET(FLEECE_DECODER_SOURCE ${FLEECE_DECODER_SOURCE} null/null_decoders.C PARENT_SCOPE)
