/*

Copyright (C) 2003 Christian Kreibich <christian.kreibich@cl.cam.ac.uk>.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>
#include <stdio.h>
#include <strings.h>
#include <syslog.h>

#include "hc_debug.h"
#include "hc_signature_hist.h"
#include "hc_file_logger.h"

FILE   *logfile;

static void
file_logger_sigprint_cb(const HC_Signature *sig, void *user_data)
{
	char sigstring[MAXPATHLEN];
	
	if (!logfile)
		return;

	hc_sig_print(sig, sigstring, MAXPATHLEN);
	fprintf(logfile, "%s\n", sigstring);
	fflush(logfile);

	return;
	user_data = 0;
}


static void      
file_logger_report_cb(void *user_data)
{
	time_t timestamp;

	timestamp = time(NULL);
	fprintf(logfile, "\n# Signature report at %s", ctime(&timestamp));
	fflush(logfile);
	
	hc_sighist_foreach(file_logger_sigprint_cb, NULL);

	return;
	user_data = 0;
}


void      
hc_file_logger_init(const char *filename)
{
	if (!filename || !*filename)
		return;
	
	if (logfile) {
		fclose(logfile);
	}
	
	D(("Honeycomb logging to %s\n", filename));

	if (! (logfile = fopen(filename, "a+"))) {
		D(("Logfile couldn't be created\n"));
		return;
	}
	
	hc_sighist_set_report_callback(file_logger_report_cb, NULL);
}
