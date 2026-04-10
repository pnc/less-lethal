1. All the locking and waiting in the test suite around apt seems too complex. Let's make the ability to pass extra cloud-init scripts/YAML a first-class feature of vm.py, and then dogfood it to get npm installed during the test suite only.
1. Extend the test suite to ensure the curl to cisco.com is blocked by default. (If not, provide a default mitmproxy filter script and ensure it's used.)
1. Extend the test suite to use nmap to see what ports are accessible on the host. The test should fail if anything besides the proxy port is exposed. (Add rationale that this protects the host machine from the VM.)
4. Simple is harder than complex. Review all code and propose 3 ways it can be simplified based on what you know now.
