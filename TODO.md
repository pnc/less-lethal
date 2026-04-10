1. Extend the test suite to ensure the curl to example.com is blocked by default. (If not, provide a default mitmproxy filter script and ensure it's used.)
1. Extend the test suite to use nmap to see what ports are accessible on the host. The test should fail if anything besides the proxy port is exposed. (Add rationale that this protects the host machine from the VM.)
4. Simple is harder than complex. Review all code and propose 3 ways it can be simplified based on what you know now.
