1. Extend the test suite to ensure the curl to example.com is blocked by default. (If not, provide a default mitmproxy filter script and ensure it's used.)
1. Extend the test suite to use nmap to see what ports are accessible on the host. The test should fail if anything besides the proxy port is exposed. (Add rationale that this protects the host machine from the VM.)
1. Move the download cache to its own . directory, maybe .images. Make reset simpler by nuking all of .vm instead of individual files.
2. The need to specify the images https urls and the QEMU commands across both backends implies the abstraction is not quite right. Perhaps normalize the detected architecture into an enum or something so that,  these do not need to be duplicated across backends
4. Simple is harder than complex. Review all code and propose 3 ways it can be simplified based on what you know now.
