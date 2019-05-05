/**
 \file Tiny Double Linked List
 Replacement for GLib's g_list_ API
 
*/


//#define TEST_TDLL

#if defined(_WIN64) || defined(_WIN32)
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include "tdll.h"


/** 
\brief Return the first element of the list 
\note Most functions assume that the given list already is the first element
*/
tdllist * tdll_first(tdllist * list)
{
	tdllist *l;
	if (list) {
		if (list->prev == NULL) return list;
		for (l = list->prev; l->prev; l = l->prev) {
			if (l == list) return NULL; // cas d'erreur : liste circulaire
		}
	} 
	return NULL;
}


/**
\brief Return the last element of the list
*/
tdllist * tdll_last(tdllist * list)
{
	tdllist *l;
	if (list) {
		if (list->next == NULL) return list;
		for (l = list->next; l; l = l->next) {
			//if (l == list) return NULL; // cas d'erreur : liste circulaire
			if (l->next == NULL) return l;
		}
	}
	return NULL;
}



/**
\brief Add an element at the end of the list
\note 
- The new list element is malloc()'ed here, and should be free()ed later
- Not very efficient since the whole list must be traversed. Use prepend if possible.
*/
tdllist * tdll_append(tdllist * list, void * item)
{
	tdllist *last = tdll_last(list);
	tdllist *l = malloc(sizeof(tdllist));
	l->data = item;
	l->prev = NULL;
	l->next = NULL;
	if (last) {
		last->next = l;
		l->prev = last;
		return list;
	} else {
		// Premier �lement de la liste
		return l;
	}
	return NULL; // cas d'erreur : code inatteignable
}


/**
\brief Add an element at the beginning of the list
\note The new list element is malloc()'ed here, and should be free()ed later
*/
tdllist * tdll_prepend(tdllist * list, void * item)
{
	if (list->prev) {
		fprintf(stderr, "tdll_prepend() : not start of list\n");
		abort();
	}

	tdllist *l = malloc(sizeof(tdllist));
	l->data = item;
	l->prev = NULL;
	l->next = NULL;

	if (list) {
		l->next = list;
		list->prev = l;
	}
	return l;
}


/**
\brief Removes an element from a list.
\note
- If two elements contain the same data, only the first is removed.
- If none of the elements contain the data, do nothing.

\param [in] 	list a GList, this must point to the top of the list
\param [in] 	data the data of the element to remove
\return 	the possibly changed) start of the list
*/
tdllist * tdll_remove(tdllist * list, void * data)
{
	if (list == NULL) return NULL;
	tdllist *l;
	for (l = list; l != NULL; l=l->next) {
		printf("%p\n", l);
		if (l->data == data) {
			// Suppression de cet element
			if (l->prev == NULL) {
				if (l->next == NULL) {
					// Cas element unique, la liste devient vide
					free(l);
					return NULL;
				} 
				else {
					// Cas on supprime le premier element
					list = list->next;
					list->prev = NULL;
					free(l);
					return list;
				}
			} 
			else if (l->next == NULL) {
				// Cas on supprime le dernier element
				l->prev->next = NULL;
				free(l);
				return list; // premier element inchange
			}
			else {
				// Cas on supprime un element au milieu de la liste, ni au debut ni a la fin
				l->prev->next = l->next;
				l->next->prev = l->prev;
				free(l);
				return list; // premier element inchange
			}
		}
	}
	// Code atteint si on a donne un 'data' pas dans la liste : dans ce cas, ne fait rien
	return list;
}


/** 
\brief Removes the node link_ from the list without freeing it. 
\note In fact, separate an element as a new one-element list
\param list[in] a list given by its first element
\param link_[in] node to separate from list
\return the (possibly changed) start of the list
\note if link_ is not in list, result will be interderminated
*/
tdllist * tdll_remove_link(tdllist * list, tdllist * link_)
{
	if ((list == NULL) || (link_ ==NULL)) return list;
	
	// cas : on détache le premier élément
	if (link_->prev == NULL) {
		if (link_ != list) {
			fprintf(stderr, "%s() runtime error at %s:%d\n", __func__, __FILE__, __LINE__);
			exit(1);
		}
	
		if (link_->next == NULL) {
			// Cas : on détache l'unique élément, la liste devient vide
			link_->next = NULL;
			link_->prev = NULL;
			return NULL;	
		} else {
			// Cas : on détache un élément au début
			list=list->next;
			link_->next = NULL;
			link_->prev = NULL;
			list ->prev = NULL;
			return list;
		}
	} else if (link_ -> next == NULL) {
		// Cas : on détache le dernier élément
		link_->prev->next = NULL;
		link_->prev = NULL;
		link_->next = NULL;
		return list;
		
	} else {
		// Cas : on détache un élément dans le milieu
		link_->prev->next = link_->next;
		link_->next->prev = link_->prev;
		link_->next=NULL;
		link_->prev=NULL;
		return list;
	}
	
	return list;
}

/**
\brief free a list, but not the data 
\note 
- The list items are free()ed
- The ->data pointer are not free()ed
*/
void tdll_free(tdllist * list)
{
	tdllist *l = list;
	while (l) {
		tdllist *ll=l->next;
		free(l);
		l=ll;
	}
}

/**
\brief Removes the node link_ from the list and frees it  
\note 
- The data is not free()ed. Must be free()ed before, or referenced in an other way
*/
tdllist * tdll_delete_link(tdllist* list, tdllist* link_) {
	if ((list == NULL) || (link_ ==NULL)) return list;
	tdllist *r = tdll_remove_link(list,link_);
	free(link_);
	return r;
}



#ifdef TEST_TDLL

void main(void) {

	tdllist *l = NULL;

	char *truc = "truc";

	l = tdll_append(l, "A"); 
	l = tdll_append(l, "B"); 
	l = tdll_append(l, "C"); 
	l = tdll_append(l, truc);
	l = tdll_append(l, "D"); 
	l = tdll_append(l, "E"); 

	l = tdll_prepend(l, "F"); 
	l = tdll_prepend(l, "G"); 
	l = tdll_prepend(l, "H"); 
	l = tdll_prepend(l, truc);

	puts("");
	for(tdllist *ll = l; ll; ll = ll->next) {
		printf("%s\n",(char*)ll->data);
	}

	getchar();
	l = tdll_remove(l, truc);

	puts("");
	for (tdllist *ll = l; ll; ll = ll->next) {
		printf("%s\n", (char*)ll->data);
	}

	getchar();
}

#endif
