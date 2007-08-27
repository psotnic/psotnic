/*******************************************************
 * Psotnic framework generated by framework.sh
 * Copyright (c) 2004-2005 Grzegorz Rusin <grusin@gmail.com>
 * Created: pon sie 27 10:26:52 CEST 2007
 * 
 * WARNING! All changes made in this file will be lost!
 */

extern void (*mem_strcpy)(char *&dest, const char *src);
extern int (*ircd_strcmp)(const char *str1, const char *str2);
extern int (*ircd_strncmp)(const char *str1, const char *str2, int n);
extern char* (*itoa)(int num);
extern chanuser* (*findUser)(const char *nick, chan *channel);
extern void (*sendToOwner)(const char *owner, char *msg);
extern void (*sendToOwners)(const char *msg);
extern int (*getPenalty)();
extern void (*privmsg)(const char *to, const char *msg);
extern void (*notice)(const char *to, const char *msg);
extern char* (*handle)();
extern char* (*nick)();
extern void (*cycle)(chan *channel, const char *reason, int rejoinDelay);
extern char* (*server)();
extern char* (*ircIp)();
extern int (*saveUserlist)(const char *file, const char *pass);
extern void (*flags2str)(int flags, const char *str);;
extern void (*setTopic)(chan *ch, const char *topic);;
extern bool (*isSticky)(const char *ban, chan *ch);;
extern int (*kick4)(chan *channel, chanuser **multHandle, int num);
extern int (*kick6)(chan *channel, chanuser **multHandle, int num);
extern int (*kick)(chan *channel, chanuser *p, const char *reason);
extern int (*match)(const char *mask, const char *str);
extern char* (*srewind)(const char *str, int word);
extern void (*str2words)(const char *word, const char *str, int x, int y, int ircstrip);
extern CHANLIST* (*findChanlist)(const char *name);
extern chan* (*findChannel)(const char *name);
extern void (*setReason)(chanuser *u, const char *reason);
extern void (*addMode)(chan *channel, const char mode[2], const char *arg, int prio, int delay);
extern void (*addKick)(chan *channel, chanuser *p, const char *reason);
extern int (*flushModeQueue)(chan *channel, int prio);
extern int (*initCustomData)(const char *Class, FUNCTION constructor, FUNCTION destructor);
extern void (*knockout)(chan *ch, chanuser *u, const char *reason, int delay);
extern char* (*httpget)(const char *link);
extern inetconn* (*findConnByHandle)(HANDLE *h);
extern inetconn* (*findConnByName)(const char *name);
