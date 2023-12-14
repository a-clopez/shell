
#include "dynamic_list.h"
#include "string.h"

tList createEmptyList(tList *pL){
    tList L = LNULL;
    *pL = L;
    return L;
}

bool isEmptyList(tList L){
    if(L==LNULL)
        return true;
    else
        return false;
}
tPosL first(tList L){
    return L;
}


tPosL next(tPosL pos,tList L){
        return pos->next;
}


bool insertItem(struct tNode node,tList *pL){
    //Create tNode
    tPosL t,p;
    t = malloc(sizeof(struct tNode));
    if (t==LNULL) {
        return false;
    }
    else{
        if(node.mem.size >= 0){
            t->mem.address=node.mem.address;
            strcpy(t->data.text,node.data.text);
            strcpy(t->mem.data.text,node.mem.data.text);
            t->mem.key=node.mem.key;
            t->mem.size=node.mem.size;
            t->mem.date=node.mem.date;
        }
    t->next =LNULL;

    //List is empty
    if(*pL==LNULL) *pL=t;
    else{
        p=*pL;
        while (p->next!=LNULL) p=p->next;
        t->next=p->next;
        p->next=t;
    }
        return true;
    }
}


void deleteAtPosition(tPosL pos,tList *pL){
    tPosL p;
    if(pos==*pL) *pL=pos->next;
    else if (pos->next==LNULL){
        for(p=*pL; p->next!=pos; p=p->next);
        p->next=LNULL;
    }
    else{
        for(p=*pL; p->next!=pos; p=p->next);
        p->next=pos->next;
    }
    free(pos);
}



struct tNode getItem(tPosL pos,tList L){
        return *pos;
}


