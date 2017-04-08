#ifndef SNORT_STREAM4_SESSION_H_
#define SNORT_STREAM4_SESSION_H_

void InitSessionCache();
void PurgeSessionCache();
Session *GetSession(Packet *);
//Session *InsertSession(Packet *, Session *);
Session *GetNewSession(Packet *);
Session *RemoveSession(Session *);
void PrintSessionCache();
int PruneSessionCache(u_int8_t proto, u_int32_t thetime, int mustdie, Session *save_me);
int GetSessionCount(Packet *p);
int DumpStateTable(const char *);

#ifdef GIDS
int TruncSessionCache(u_int8_t, u_int32_t, int, Session *);
#endif /* GIDS */

#if defined(USE_HASH_TABLE) || defined(USE_SPLAY_TREE)
Session *GetSession(Packet *);
#endif

#endif /* SNORT_STREAM4_SESSION_H_ */

