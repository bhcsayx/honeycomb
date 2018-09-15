## Process this file with automake to produce Makefile.in

LIBS                  = -lstree -levent
INCLUDES	      = -I@dnet_cflags@ -I@hd_includedir@ -I$(top_srcdir) -I$(top_srcdir)/src -W -Wall

bin_PROGRAMS	      = honeycomb

honeycomb_SOURCES  = \
	honeycomb.c honeycomb.h \
	hc_debug.h \
	hc_config.c hc_config.h \
	hc_conn.c hc_conn.h \
	hc_ip.c hc_ip.h \
	hc_tcp.c hc_tcp.h \
	hc_tcp_conn.c hc_tcp_conn.h \
	hc_udp.c hc_udp.h \
	hc_udp_conn.c hc_udp_conn.h \
	hc_bitmaps.c hc_bitmaps.h \
	hc_file_logger.c hc_file_logger.h \
	hc_signature.c hc_signature.h \
	hc_signature_hist.c hc_signature_hist.h \
	hc_snort_printer.c hc_snort_printer.h \
	hc_string_alg.c hc_string_alg.h \
	hc_util.c hc_util.h \
	hc_pcap_handler.h

honeycomb_LDFLAGS  = -module -avoid-version
