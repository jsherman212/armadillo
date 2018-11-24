/*
Implementation for a singly linked list.
*/

#include "linkedlist.h"

struct linkedlist *linkedlist_new(void){
	struct linkedlist *list = malloc(sizeof(struct linkedlist));

	if(!list)
		return NULL;
	
	list->front = NULL;

	return list;
}

// should be only called to set up the linked list
// if we need to add more things, use add
void linkedlist_add_front(struct linkedlist *list, void *data){
	if(!list->front){
		list->front = malloc(sizeof(struct node_t));
		list->front->next = NULL;
		list->front->data = data;
	}
}

void linkedlist_add(struct linkedlist *list, void *data_to_add){
	// empty list
	if(!list->front){
		linkedlist_add_front(list, data_to_add);
		return;
	}

	if(!data_to_add)
		return;

	struct node_t *current = list->front;

	while(current->next)
		current = current->next;

	struct node_t *add = malloc(sizeof(struct node_t));
	add->data = data_to_add;
	add->next = NULL;

	current->next = add;
}

int linkedlist_contains(struct linkedlist *list, void *data){
	if(!list->front)
		return 0;

	struct node_t *current = list->front;

	while(current->next){
		if(current->data == data)
			return 1;

		current = current->next;
	}

	return 0;
}

void linkedlist_delete(struct linkedlist *list, void *data_to_remove){
	// empty list
	if(!list->front)
		return;

	if(!data_to_remove)
		return;

	// removing front
	if(list->front->data == data_to_remove){
		list->front = list->front->next;
		return;
	}

	struct node_t *current = list->front;
	struct node_t *previous = NULL;

	while(current->next){
		previous = current;
		current = current->next;

		if(current->data == data_to_remove){
			// now we are at the node before the node we want to remove, modify connections to skip the one we're trying to remove
			previous->next = current->next;
			free(current);
			current = NULL;
			return;
		}
	}
}

void linkedlist_free(struct linkedlist *list){
	free(list);
	list = NULL;
}
