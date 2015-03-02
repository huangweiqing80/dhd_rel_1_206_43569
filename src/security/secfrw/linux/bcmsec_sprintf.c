/*****************************************************************************
 *
 *****************************************************************************
*/

#include <stdio.h>
#include <stdarg.h>

void
bcmsec_sprintf(void *ctx, const char fmtstr[], ...)
{
	va_list ap;

	printf("(ctx:%p) ", ctx);

	va_start(ap, fmtstr);
	vprintf(fmtstr, ap);
	va_end(ap);
}
