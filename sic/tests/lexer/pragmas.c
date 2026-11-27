// #pragma pack and GCC visibility, in their forms; tokens carry what is in force.
#pragma pack(push, 2)
struct a { char c; int i; };
#pragma pack(pop)
#pragma pack(4)
struct b { char c; int i; };
#pragma pack()
#pragma pack(push, id, 8)
struct c { char c; double d; };
#pragma pack(push)
#pragma pack(1)
struct d { char c; int i; };
#pragma pack(pop, id)
#pragma pack(3)
#pragma pack(+2)
#pragma pack(256)
#pragma pack( , 16 )
#pragma pack(show)
struct e { char c; int i; };
#pragma pack(pop)
#pragma pack(pop)
#pragma GCC visibility push(hidden)
int hidden_one;
#pragma GCC visibility push( default )
int shown;
#pragma GCC visibility push(internal)
int internal_one;
#pragma GCC visibility pop
#pragma GCC visibility pop
int still_hidden;
#pragma GCC visibility pop
#pragma GCC visibility pop
int visible;
#pragma once
#pragma GCC diagnostic push
int last;
