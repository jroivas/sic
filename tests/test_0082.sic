/* Most of this is copied from cpp output ie. coming from glibc and gcc headers */
typedef unsigned short int sa_family_t;
typedef unsigned int __socklen_t;
typedef __socklen_t socklen_t;

struct sockaddr
{
    sa_family_t sa_family;
    char sa_data[14];
};

extern int bind(int __fd, const struct sockaddr * __addr, socklen_t __len)
     __attribute__ ((__nothrow__ , __leaf__));

int main()
{
    return 0;
}
