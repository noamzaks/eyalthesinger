# Crackers (`crackers`)

The `sing` binary is composed of C implementation of crytographic functions. It's supposed to be very minimal and to inline as many functions as possible and use as many compiler optimizations as possible.

In the future, we'll need to understand how we can parallelize this with CUDA.

# Python (`src`)

The Python library should perform any necessary pre-processing and tasks which don't necessarily have to be performant. This makes development easier.
The Python library is also in charge of CPU parallelization and parallelization across the network.
