#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libstree.h>
#include "honeycomb.h"
#include "hc_ip.h"
#include "hc_udp.h"
#include "hc_udp_conn.h"
#include "hc_tcp.h"
#include "hc_tcp_conn.h"
#include "hc_signature.h"
#include "hc_signature_hist.h"
#include "hc_snort_printer.h"
#include "hc_file_logger.h"
#include "hc_config.h"
#include "hc_pcap_handler.h"

int main(int argc,char *argv[])
{
    	/* First of all, initialize config to default settings */
	hc_config_init();

	//printf(("Initializing Honeycomb %s\n", VERSION));

	/* Initialize libstree -- we want to use its algorithms on
	 * binary data, so set the printer function to hex output.
	 * The other default string handling implementations are
	 * correct by default.
	 */
	lst_stringclass_set_defaults(NULL, NULL, lst_string_print_hex);

	/* Initialize the protocol handlers -- they hook
	 * themselves into Honeyd's packet rx/tx code
	 */
	hc_ip_init();
	hc_udp_init();
	hc_tcp_init();

	/* Initialize TCP and UDP stream reassemblers. */
	hc_udp_conn_init();
	hc_tcp_conn_init();

	/* Print Snort rules for now -- this should really
	 * rather be user-configurable.
	 */
	hc_sig_set_printer(hc_sig_print_snort);

	/* Initialize signature history. It prevents us from
	 * reporting duplicate signatures.
	 */
	hc_sighist_init();
	hc_sighist_set_max_size(hc_config.sighist_max_size);

	/* Initialize the signature output mechanism. This
	 * should be much more configurable, but for now
	 * we just print to a logfile.
	 */
	hc_file_logger_init(hc_config.sig_output_file);

	/* Analyze input pcap file */
    hc_pcap_handler(argv[1]);
}
