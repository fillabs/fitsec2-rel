#ifdef WIN32
#include <windows.h>

void usleep(__int64 usec) 
{ 
    HANDLE timer; 
    LARGE_INTEGER ft; 

    ft.QuadPart = -(10*usec); // Convert to 100 nanosecond interval, negative value indicates relative time

    timer = CreateWaitableTimer(NULL, TRUE, NULL); 
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0); 
    WaitForSingleObject(timer, INFINITE); 
    CloseHandle(timer); 
}
#endif

#include <time.h>
#include <stdio.h>
#include <string.h>
int strpdate(const char* s, struct tm* t)
{
    memset(t, 0, sizeof(struct tm));
    if (3 == sscanf(s, "%d-%d-%d", &t->tm_year, &t->tm_mon, &t->tm_mday)) {
        if (t->tm_year >= 1900 &&
            t->tm_mon >= 1 && t->tm_mon <= 12 &&
            t->tm_mday >= 1 && t->tm_mday <= 31) {
            t->tm_year -= 1900;
            t->tm_mon--;
            return 0;
        }
    }
    return -1;
}

#ifdef __CYGWIN__
int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
  struct timeval xx = *x;
  struct timeval yy = *y;
  x = &xx; y = &yy;

  if (x->tv_usec > 999999)
  {
    x->tv_sec += x->tv_usec / 1000000;
    x->tv_usec %= 1000000;
  }

  if (y->tv_usec > 999999)
  {
    y->tv_sec += y->tv_usec / 1000000;
    y->tv_usec %= 1000000;
  }

  result->tv_sec = x->tv_sec - y->tv_sec;

  if ((result->tv_usec = x->tv_usec - y->tv_usec) < 0)
  {
    result->tv_usec += 1000000;
    result->tv_sec--; // borrow
  }

  return result->tv_sec < 0;
}
#endif
