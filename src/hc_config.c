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

#include <string.h>

#include <honeyd/plugins_config.h>
#include <honeyd/debug.h>
#include "honeycomb.h"
#include "hc_config.h"

HC_Config hc_config;

void
hc_config_init(void)
{
	const struct honeyd_plugin_cfg *cfg;

	/* First, initialize to default values: */

	hc_config.snort_alert_class                  = strdup("honeyd");

	hc_config.ip_backlog                         = 100;

	hc_config.udp_conns_max                      = 1000;
	hc_config.udp_dataconns_max                  = 100;
	hc_config.udp_max_msg_size                   = 5000;
	hc_config.udp_max_bytes                      = 10000;
	hc_config.udp_pattern_minlen                 = 5;

	hc_config.tcp_conns_max                      = 65000;
	hc_config.tcp_dataconns_max                  = 1000;
	hc_config.tcp_max_msg_size                   = 5000;
	hc_config.tcp_max_bytes                      = 10000;
	hc_config.tcp_max_buffering_in               = 1000;
	hc_config.tcp_pattern_minlen                 = 5;

	hc_config.conns_hash_slots                   = 199;
	hc_config.conns_hash_cleanup_interval        = 10;

	hc_config.sighist_max_size                   = 200;
	hc_config.sighist_interval                   = 30;
	hc_config.sig_output_file                    = strdup("/home/hc/honeycomb.log");	


	/* Now, let's see what we can get from honeyd, and update
	 * the settings accordingly.
	 */
/*	if ( (cfg = plugins_config_find_item(PACKAGE, "snort_alert_class", HD_CONFIG_STR))) {
		if (hc_config.snort_alert_class)
			free(hc_config.snort_alert_class);
		hc_config.snort_alert_class = strdup(cfg->cfg_str);
	}

	if ( (cfg = plugins_config_find_item(PACKAGE, "sig_output_file", HD_CONFIG_STR))) {
		if (hc_config.sig_output_file)
			free(hc_config.sig_output_file);
		hc_config.sig_output_file = strdup(cfg->cfg_str);
	}

	if ( (cfg = plugins_config_find_item(PACKAGE, "ip_backlog", HD_CONFIG_INT)))
		hc_config.ip_backlog = cfg->cfg_int;


	if ( (cfg = plugins_config_find_item(PACKAGE, "udp_conns_max", HD_CONFIG_INT)))
		hc_config.udp_conns_max = cfg->cfg_int;

	if ( (cfg = plugins_config_find_item(PACKAGE, "udp_dataconns_max", HD_CONFIG_INT)))
		hc_config.udp_dataconns_max = cfg->cfg_int;

	if ( (cfg = plugins_config_find_item(PACKAGE, "udp_max_msg_size", HD_CONFIG_INT)))
		hc_config.udp_max_msg_size = cfg->cfg_int;

	if ( (cfg = plugins_config_find_item(PACKAGE, "udp_max_bytes", HD_CONFIG_INT)))
		hc_config.udp_max_bytes = cfg->cfg_int;

	if ( (cfg = plugins_config_find_item(PACKAGE, "udp_pattern_minlen", HD_CONFIG_INT)))
		hc_config.udp_pattern_minlen = cfg->cfg_int;
		

	if ( (cfg = plugins_config_find_item(PACKAGE, "tcp_conns_max", HD_CONFIG_INT)))
		hc_config.tcp_conns_max = cfg->cfg_int;

	if ( (cfg = plugins_config_find_item(PACKAGE, "tcp_dataconns_max", HD_CONFIG_INT)))
		hc_config.tcp_dataconns_max = cfg->cfg_int;
		
	if ( (cfg = plugins_config_find_item(PACKAGE, "tcp_max_msg_size", HD_CONFIG_INT)))
		hc_config.tcp_max_msg_size = cfg->cfg_int;
		
	if ( (cfg = plugins_config_find_item(PACKAGE, "tcp_max_bytes", HD_CONFIG_INT)))
		hc_config.tcp_max_bytes = cfg->cfg_int;
		
	if ( (cfg = plugins_config_find_item(PACKAGE, "tcp_max_buffering_in", HD_CONFIG_INT)))
		hc_config.tcp_max_buffering_in = cfg->cfg_int;
		
	if ( (cfg = plugins_config_find_item(PACKAGE, "tcp_pattern_minlen", HD_CONFIG_INT)))
		hc_config.tcp_pattern_minlen = cfg->cfg_int;
		

	if ( (cfg = plugins_config_find_item(PACKAGE, "conns_hash_slots", HD_CONFIG_INT)))
		hc_config.conns_hash_slots = cfg->cfg_int;

	if ( (cfg = plugins_config_find_item(PACKAGE, "conns_hash_cleanup_interval", HD_CONFIG_INT)))
		hc_config.conns_hash_cleanup_interval = cfg->cfg_int;
		

	if ( (cfg = plugins_config_find_item(PACKAGE, "sighist_max_size", HD_CONFIG_INT)))
		hc_config.sighist_max_size = cfg->cfg_int;
	
	if ( (cfg = plugins_config_find_item(PACKAGE, "sighist_interval", HD_CONFIG_INT)))
		hc_config.sighist_interval = cfg->cfg_int;*/
}	
