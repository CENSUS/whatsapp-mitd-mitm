#ifndef _LOG_H_
#define _LOG_H_

#define TAG "CENSUS"

void log(const char *, ...);
void log_error(const char *, ...);
void log_perror(const char *);

#endif /* _LOG_H_ */
