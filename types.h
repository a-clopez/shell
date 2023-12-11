
#ifndef SO_TYPES_H
#define SO_TYPES_H



#define NAME_LENGTH_LIMIT 200
#include <stdbool.h>
#include <time.h>
typedef struct tData{
    char text[NAME_LENGTH_LIMIT];
}tData;

struct tItemL{
    void * address;
    tData data;
    size_t size;
    int key;
    time_t date;
};

#endif //SO_TYPES_H
