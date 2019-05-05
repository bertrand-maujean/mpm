#ifndef HAVE_TDLL_H
#define HAVE_TDLL_H

#include <malloc.h>
#ifdef TEST_TDLL
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tdllist {
	void *data;
	struct tdllist *next;
	struct tdllist *prev;
} tdllist;

tdllist *tdll_first(tdllist* list);
tdllist *tdll_last (tdllist* list);
tdllist * tdll_append (tdllist* list, void* item);
tdllist * tdll_prepend(tdllist* list, void* item);
tdllist * tdll_remove(tdllist* list,  void *item );
tdllist * tdll_delete_link(tdllist* list, tdllist*link_);
void tdll_free(tdllist* list);


#ifdef __cplusplus
}
#endif

#endif /* HAVE_TDLL_H */