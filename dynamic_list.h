
#ifndef DYNAMIC_LIST_H
#define DYNAMIC_LIST_H

#include "types.h"
#include <stdio.h>
#include <stdlib.h>

#define LNULL NULL

typedef struct tNode *tPosL;
struct tNode{
    tData data;
    struct tItemL mem;
    tPosL next;
};
typedef tPosL tList;


tList createEmptyList(tList *L);
bool isEmptyList(tList L);
tPosL first(tList L);
tPosL next(tPosL pos,tList L);
bool insertItem(struct tNode node,tList *pL);
void  deleteAtPosition(tPosL pos,tList *pL);
struct tNode getItem(tPosL pos,tList L);

#endif
