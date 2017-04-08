#ifndef SNORT_STREAM4_SAVESTATE_H_
#define SNORT_STREAM4_SAVESTATE_H_

int DumpStateTable(const char *path);
int LoadStateTable(const u_int32_t thetime, const char *path);

#endif
