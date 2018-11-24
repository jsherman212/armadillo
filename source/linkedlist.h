#ifndef _LINKEDLIST_H_
#define _LINKEDLIST_H_

#include <stdlib.h>

struct node_t {
	void *data;
	struct node_t *next;
};

struct linkedlist {
	struct node_t *front;
};

struct linkedlist *linkedlist_new(void);
void linkedlist_add_front(struct linkedlist *, void *);
void linkedlist_add(struct linkedlist *, void *);
int linkedlist_contains(struct linkedlist *, void *);
void linkedlist_delete(struct linkedlist *, void *);
void linkedlist_free(struct linkedlist *);

#endif
