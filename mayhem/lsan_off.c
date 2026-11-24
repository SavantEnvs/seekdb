/* Disable LeakSanitizer at build time for every ASan-built fuzz target (leaks are not the bug
 * class fuzzed here); ASan itself stays fully on. Linked into each binary by mayhem/build.sh. */
int __lsan_is_turned_off(void) { return 1; }
