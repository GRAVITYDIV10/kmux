#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include "kermit.h"

#define zabort assert

void kermit_selftest(void) {
	zabort(0 == 0);
	//zabort(0 == 1);

	zabort(kermit_tochar(0) == 32);
	zabort(kermit_tochar(94) == 126);
	zabort(kermit_unchar(32) == 0);
	zabort(kermit_unchar(126) == 94);
	zabort(kermit_toctl(0) == 64);
	zabort(kermit_toctl(31) == 95);
	zabort(kermit_toctl(127) == 63);

	int8_t xpkt[KERMIT_XPKT_MAXLEN];
	xpkt[KERMIT_OFFSET_MARK] = 0x55;
	zabort(kermit_mark_get(xpkt) == 0x55);
	zabort(kermit_mark_chk(xpkt) == 0);
	kermit_mark_set(xpkt, 0x1);
	zabort(kermit_mark_get(xpkt) == 0x1);
	zabort(kermit_mark_chk(xpkt) != 0);

	xpkt[KERMIT_OFFSET_BLEN] = kermit_tochar(2);
	zabort(kermit_blen_get(xpkt) == 4);
	zabort(kermit_blen_chk(xpkt) == 0);

	kermit_blen_set(xpkt, 5);
	zabort(kermit_blen_get(xpkt) == 5);
	zabort(kermit_blen_chk(xpkt) == 1);

	kermit_blen_set(xpkt, 96);
	zabort(kermit_blen_get(xpkt) == 96);
	zabort(kermit_blen_chk(xpkt) == 1);

	kermit_blen_set(xpkt, 97);
	zabort(kermit_blen_get(xpkt) == 97);
	zabort(kermit_blen_chk(xpkt) == 0);

	xpkt[KERMIT_OFFSET_SEQ] = kermit_tochar(64);
	zabort(kermit_seq_get(xpkt) == 64);
	zabort(kermit_seq_chk(xpkt) == 0);
	kermit_seq_set(xpkt, 0);
	zabort(kermit_seq_get(xpkt) == 0);
	zabort(kermit_seq_chk(xpkt) == 1);
	kermit_seq_set(xpkt, 63);
	zabort(kermit_seq_get(xpkt) == 63);
	zabort(kermit_seq_chk(xpkt) == 1);

	xpkt[KERMIT_OFFSET_TYPE] = 31;
	zabort(kermit_type_get(xpkt) == 31);
	zabort(kermit_type_chk(xpkt) == 0);
	kermit_type_set(xpkt, 32);
	zabort(kermit_type_get(xpkt) == 32);
	zabort(kermit_type_chk(xpkt) == 1);
	kermit_type_set(xpkt, 127);
	zabort(kermit_type_get(xpkt) == 127);
	zabort(kermit_type_chk(xpkt) == 0);

	xpkt[KERMIT_OFFSET_LX1] = kermit_tochar(95);
	zabort(kermit_lx1_get(xpkt) == 95);
	zabort(kermit_lx1_chk(xpkt) == 0);
	kermit_lx1_set(xpkt, 0);
	zabort(kermit_lx1_get(xpkt) == 0);
	zabort(kermit_lx1_chk(xpkt) == 1);
	kermit_lx1_set(xpkt, 94);
	zabort(kermit_lx1_get(xpkt) == 94);
	zabort(kermit_lx1_chk(xpkt) == 1);

	xpkt[KERMIT_OFFSET_LX2] = kermit_tochar(95);
	zabort(kermit_lx2_get(xpkt) == 95);
	zabort(kermit_lx2_chk(xpkt) == 0);
	kermit_lx2_set(xpkt, 0);
	zabort(kermit_lx2_get(xpkt) == 0);
	zabort(kermit_lx2_chk(xpkt) == 1);
	kermit_lx2_set(xpkt, 94);
	zabort(kermit_lx2_get(xpkt) == 94);
	zabort(kermit_lx2_chk(xpkt) == 1);

	kermit_lx1_set(xpkt, 10);
	kermit_lx2_set(xpkt, 3);
	zabort(kermit_xlen_get(xpkt) == (10 * 95) + 3 + KERMIT_XHDR_SIZE);
	kermit_xlen_set(xpkt, 1000);
	zabort(kermit_xlen_get(xpkt) == 1000);
	zabort(kermit_xlen_chk(xpkt) == 1);

	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN);
	zabort(kermit_xlen_get(xpkt) == KERMIT_XPKT_MINLEN);
	zabort(kermit_xlen_chk(xpkt) == 1);

	kermit_xlen_set(xpkt, KERMIT_XPKT_MAXLEN);
	zabort(kermit_xlen_get(xpkt) == KERMIT_XPKT_MAXLEN);
	zabort(kermit_xlen_chk(xpkt) == 1);

	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN - 1);
	zabort(kermit_xlen_get(xpkt) == KERMIT_XPKT_MINLEN - 1);
	zabort(kermit_xlen_chk(xpkt) == 0);

	kermit_xlen_set(xpkt, KERMIT_XPKT_MAXLEN + 1);
	zabort(kermit_xlen_get(xpkt) == KERMIT_XPKT_MAXLEN + 1);
	zabort(kermit_xlen_chk(xpkt) == 0);

	kermit_blen_set(xpkt, 2);
	zabort(kermit_is_bpkt(xpkt) == 0);
	zabort(kermit_is_xpkt(xpkt) == 1);

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	zabort(kermit_is_bpkt(xpkt) == 1);
	zabort(kermit_is_xpkt(xpkt) == 0);

	kermit_blen_set(xpkt, 10);
	zabort(kermit_len_get(xpkt) == 10);

	kermit_blen_set(xpkt, KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE);
	kermit_xlen_set(xpkt, 100);
	zabort(kermit_len_get(xpkt) == 100);

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	kermit_seq_set(xpkt, KERMIT_SEQ_MIN);
	kermit_type_set(xpkt, 'Y');
	// 0x23 + 0x20 + 0x59 = 156
	// ((156 + ((156 >> 6) & 3)) & 0x3f) + 32 = 62
	zabort(kermit_sum1_compute(xpkt + KERMIT_OFFSET_BLEN, 3) == 62);

	kermit_blen_set(xpkt, KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE);
	kermit_seq_set(xpkt, KERMIT_SEQ_MIN);
	kermit_type_set(xpkt, 'Y');
	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN);
	// 0x20 + 0x20 + 0x59 + 0x20 + 0x21 = 218
	// ((218 + ((218 >> 6) & 3)) & 0x3f) + 32 = 61
	zabort(kermit_sum1_compute(xpkt + KERMIT_OFFSET_BLEN, 5) == 61);

	xpkt[KERMIT_OFFSET_HSUM] = 0x1F;
	zabort(kermit_hsum_get(xpkt) == 0x1F);
	zabort(kermit_hsum_compute(xpkt) == 61);
	zabort(kermit_hsum_chk(xpkt) == 0);

	kermit_hsum_set(xpkt, kermit_hsum_compute(xpkt));
	zabort(kermit_hsum_get(xpkt) == 61);
	zabort(kermit_hsum_compute(xpkt) == 61);
	zabort(kermit_hsum_chk(xpkt) == 1);

	int8_t xparam[KERMIT_EPARAM_SIZE];
	xparam[KERMIT_PARAM_OFFSET_MAXBLEN] = kermit_tochar(80);
	zabort(kermit_maxblen_get(xparam) == 82);
	zabort(kermit_maxblen_chk(xparam) == 1);
	kermit_maxblen_set(xparam, 96);
	zabort(kermit_maxblen_get(xparam) == 96);
	zabort(kermit_maxblen_chk(xparam) == 1);
	kermit_maxblen_set(xparam, 97);
	zabort(kermit_maxblen_get(xparam) == 97);
	zabort(kermit_maxblen_chk(xparam) == 0);
	kermit_maxblen_set(xparam, 0);
	zabort(kermit_maxblen_get(xparam) == 0);
	zabort(kermit_maxblen_chk(xparam) == 0);
	kermit_maxblen_set(xparam, 82);
	zabort(kermit_maxblen_get(xparam) == 82);
	zabort(kermit_maxblen_chk(xparam) == 1);

	xparam[KERMIT_PARAM_OFFSET_QCTL] = '(';
	zabort(kermit_qctl_get(xparam) == '(');
	kermit_qctl_set(xparam, 'A');
	zabort(kermit_qctl_get(xparam) == 'A');
	zabort(kermit_qctl_chk(xparam) == 0);
	kermit_qctl_set(xparam, '#');
	zabort(kermit_qctl_get(xparam) == '#');
	zabort(kermit_qctl_chk(xparam) == 1);

	xparam[KERMIT_PARAM_OFFSET_QBIN] = 'Y';
	zabort(kermit_qbin_get(xparam) == '&');
	zabort(kermit_qbin_chk(xparam) == 1);
	kermit_qbin_set(xparam, '#');
	zabort(kermit_qbin_get(xparam) == '#');
	zabort(kermit_qbin_chk(xparam) == 1);

	zabort(kermit_qctl_valid(xparam) == 0);
	zabort(kermit_qbin_valid(xparam) == 0);
	kermit_qctl_set(xparam, '#');
	kermit_qbin_set(xparam, '&');
	zabort(kermit_qctl_valid(xparam) == 1);
	zabort(kermit_qbin_valid(xparam) == 1);
	kermit_qctl_set(xparam, '#');
	kermit_qbin_set(xparam, 'Y');
	zabort(kermit_qctl_valid(xparam) == 1);
	zabort(kermit_qbin_valid(xparam) == 1);
	kermit_qctl_set(xparam, ' ');
	zabort(kermit_qctl_valid(xparam) == 0);
	kermit_qctl_set(xparam, '#');
	kermit_qbin_set(xparam, ' ');
	zabort(kermit_qbin_valid(xparam) == 0);
	kermit_qbin_set(xparam, 'Y');

	xparam[KERMIT_PARAM_OFFSET_CHKT] = '1';
	zabort(kermit_chkt_get(xparam) == '1');
	zabort(kermit_chkt_chk(xparam) == 1);
	kermit_chkt_set(xparam, '2');
	zabort(kermit_chkt_get(xparam) == '2');
	zabort(kermit_chkt_chk(xparam) == 1);
	kermit_chkt_set(xparam, 'A');
	zabort(kermit_chkt_get(xparam) == 'A');
	zabort(kermit_chkt_chk(xparam) == 0);

	xparam[KERMIT_PARAM_OFFSET_REPT] = '~';
	zabort(kermit_rept_get(xparam) == '~');
	zabort(kermit_rept_chk(xparam) == 0);
	kermit_rept_set(xparam, ' ');
	zabort(kermit_rept_get(xparam) == ' ');
	zabort(kermit_rept_chk(xparam) == 1);

	xparam[KERMIT_PARAM_OFFSET_CAPAS] = kermit_tochar(7);
	zabort(kermit_capas_get(xparam) == 7);
	zabort(kermit_capas_chk(xparam) == 0);

	kermit_capas_set(xparam, 0);
	zabort(kermit_capas_get(xparam) == 0);
	zabort(kermit_capas_chk(xparam) == 1);
	zabort(kermit_xlen_valid(xparam) == 0);

	kermit_capas_set(xparam, KERMIT_CAPAS_XLEN);
	zabort(kermit_capas_get(xparam) == KERMIT_CAPAS_XLEN);
	zabort(kermit_capas_chk(xparam) == 1);
	zabort(kermit_xlen_valid(xparam) == 1);

	xparam[KERMIT_PARAM_OFFSET_MAXLX1] = kermit_tochar(95);
	zabort(kermit_maxlx1_get(xparam) == 95);
	zabort(kermit_maxlx1_chk(xparam) == 0);

	kermit_maxlx1_set(xparam, 20);
	zabort(kermit_maxlx1_get(xparam) == 20);
	zabort(kermit_maxlx1_chk(xparam) == 1);

	kermit_maxlx1_set(xparam, 94);
	zabort(kermit_maxlx1_get(xparam) == 94);
	zabort(kermit_maxlx1_chk(xparam) == 1);

	xparam[KERMIT_PARAM_OFFSET_MAXLX2] = kermit_tochar(95);
	zabort(kermit_maxlx2_get(xparam) == 95);
	zabort(kermit_maxlx2_chk(xparam) == 0);
	kermit_maxlx2_set(xparam, 20);
	zabort(kermit_maxlx2_get(xparam) == 20);
	zabort(kermit_maxlx2_chk(xparam) == 1);
	kermit_maxlx2_set(xparam, 94);
	zabort(kermit_maxlx2_get(xparam) == 94);
	zabort(kermit_maxlx2_chk(xparam) == 1);

	kermit_maxlx1_set(xparam, 50);
	kermit_maxlx2_set(xparam, 70);
	zabort(kermit_maxlx_get(xparam) == ((50 * 95) + 70 + KERMIT_XHDR_SIZE));
	zabort(kermit_maxlx_chk(xparam) == 1);

	kermit_maxlx_set(xparam, 7);
	zabort(kermit_maxlx_get(xparam) == 7);
	zabort(kermit_maxlx_chk(xparam) == 0);

	kermit_maxlx_set(xparam, KERMIT_XPKT_MAXLEN);
	zabort(kermit_maxlx_get(xparam) == KERMIT_XPKT_MAXLEN);
	zabort(kermit_maxlx_chk(xparam) == 1);

	kermit_maxblen_set(xparam, KERMIT_BPKT_MAXLEN);
	kermit_maxlx_set(xparam, KERMIT_XPKT_MAXLEN);

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	zabort(kermit_len_get(xpkt) == KERMIT_BPKT_MINLEN);
	zabort(kermit_len_chk(xpkt, xparam) == 1);

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN - 1);
	zabort(kermit_len_get(xpkt) == KERMIT_BPKT_MINLEN - 1);
	zabort(kermit_len_chk(xpkt, xparam) == 0);

	kermit_blen_set(xpkt, KERMIT_BPKT_MAXLEN);
	zabort(kermit_len_get(xpkt) == KERMIT_BPKT_MAXLEN);
	zabort(kermit_len_chk(xpkt, xparam) == 1);

	kermit_blen_set(xpkt, KERMIT_BPKT_MAXLEN + 1);
	zabort(kermit_len_get(xpkt) == KERMIT_BPKT_MAXLEN + 1);
	zabort(kermit_len_chk(xpkt, xparam) == 0);

	kermit_blen_set(xpkt, KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE);

	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN);
	zabort(kermit_len_get(xpkt) == KERMIT_XPKT_MINLEN);
	zabort(kermit_len_chk(xpkt, xparam) == 1);

	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN - 1);
	zabort(kermit_len_get(xpkt) == KERMIT_XPKT_MINLEN - 1);
	zabort(kermit_len_chk(xpkt, xparam) == 0);

	kermit_xlen_set(xpkt, KERMIT_XPKT_MAXLEN);
	zabort(kermit_len_get(xpkt) == KERMIT_XPKT_MAXLEN);
	zabort(kermit_len_chk(xpkt, xparam) == 1);

	kermit_xlen_set(xpkt, KERMIT_XPKT_MAXLEN + 1);
	zabort(kermit_len_get(xpkt) == (KERMIT_XPKT_MAXLEN + 1));
	zabort(kermit_len_chk(xpkt, xparam) == 0);

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	kermit_len_plus(xpkt, 1);
	zabort(kermit_len_get(xpkt) == (KERMIT_BPKT_MINLEN + 1));
	kermit_len_plus(xpkt, -1);
	zabort(kermit_len_get(xpkt) == KERMIT_BPKT_MINLEN);

	kermit_blen_set(xpkt, KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE);
	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN);
	kermit_len_plus(xpkt, 1);
	zabort(kermit_len_get(xpkt) == (KERMIT_XPKT_MINLEN + 1));
	kermit_len_plus(xpkt, -1);
	zabort(kermit_len_get(xpkt) == KERMIT_XPKT_MINLEN);

	kermit_maxblen_set(xparam, KERMIT_BPKT_MAXLEN);
	kermit_maxlx_set(xparam, KERMIT_XPKT_MAXLEN);
	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	zabort(kermit_len_ava_get(xpkt, xparam) ==
		(KERMIT_BPKT_MAXLEN - KERMIT_BPKT_MINLEN));
	kermit_blen_set(xpkt, KERMIT_BPKT_MAXLEN);
	zabort(kermit_len_ava_get(xpkt, xparam) == 0);

	kermit_blen_set(xpkt, (KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE));
	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN);
	zabort(kermit_len_ava_get(xpkt, xparam) == 
		(KERMIT_XPKT_MAXLEN - KERMIT_XPKT_MINLEN));

	kermit_xlen_set(xpkt, KERMIT_XPKT_MAXLEN);
	zabort(kermit_len_ava_get(xpkt, xparam) == 0);

	kermit_chkt_set(xparam, '2');
	zabort(kermit_chkt_len_get(xparam) == 2);
	kermit_chkt_set(xparam, '3');
	zabort(kermit_chkt_len_get(xparam) == 3);
	kermit_chkt_set(xparam, '5');
	zabort(kermit_chkt_len_get(xparam) == 3);
	kermit_chkt_set(xparam, '1');
	zabort(kermit_chkt_len_get(xparam) == 1);

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	zabort(kermit_data_ava_get(xpkt, xparam) ==
		(KERMIT_BPKT_MAXLEN - KERMIT_BPKT_MINLEN - 1));

	kermit_blen_set(xpkt, KERMIT_BPKT_MAXLEN);
	zabort(kermit_data_ava_get(xpkt, xparam) == -1);

	kermit_blen_set(xpkt, KERMIT_BPKT_MAXLEN);
	zabort(kermit_data_ava_get(xpkt, xparam) == -1);

	kermit_blen_set(xpkt, (KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE));
	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN);
	zabort(kermit_data_ava_get(xpkt, xparam) == 
		(KERMIT_XPKT_MAXLEN - KERMIT_XPKT_MINLEN - 1));

	kermit_xlen_set(xpkt, KERMIT_XPKT_MAXLEN);
	zabort(kermit_data_ava_get(xpkt, xparam) == -1);

	kermit_chkt_set(xparam, '3');
	zabort(kermit_data_ava_get(xpkt, xparam) == -3);

	kermit_chkt_set(xparam, '2');
	zabort(kermit_data_ava_get(xpkt, xparam) == -2);

	kermit_chkt_set(xparam, '1');
	zabort(kermit_data_ava_get(xpkt, xparam) == -1);

	zabort(kermit_is_control(0) == 1);
	zabort(kermit_is_control(127) == 1);
	zabort(kermit_is_control(31) == 1);

	void kermit_encode_table_dump(int8_t *param);
	//kermit_qctl_set(xparam, '#');
	//kermit_qbin_set(xparam, '&');
	//kermit_encode_table_dump(xparam);

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	zabort(kermit_data_offset_get(xpkt) == 4);
	kermit_blen_set(xpkt, KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE);
	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN);
	zabort(kermit_data_offset_get(xpkt) == 7);

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	kermit_seq_set(xpkt, 0);
	kermit_type_set(xpkt, 'Y');
	int8_t sumret[KERMIT_SUM_MAXSIZE];
	zabort(kermit_sum_compute(xpkt, xparam, sumret) == 1);
	// 0x23 + 0x20 + 0x59 = 156
	// ((156 + ((156 >> 6) & 3)) & 0x3f) + 32 = 62
	zabort(sumret[0] == 62);
	kermit_seq_set(xpkt, 1);
	zabort(kermit_sum_compute(xpkt, xparam, sumret) == 1);
	zabort(sumret[0] == 63);

	kermit_chkt_set(xparam, '2');
	kermit_blen_set(xpkt, KERMIT_BPKT_MAXLEN);
	zabort(kermit_sum_offset_get(xpkt, xparam) == (KERMIT_BPKT_MAXLEN - 2));

	kermit_chkt_set(xparam, '1');
	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	zabort(kermit_sum_offset_get(xpkt, xparam) == (KERMIT_BPKT_MINLEN - 1));

	kermit_blen_set(xpkt, KERMIT_MARK_SIZE + KERMIT_BLEN_SIZE);
	kermit_xlen_set(xpkt, KERMIT_XPKT_MINLEN);
	zabort(kermit_sum_offset_get(xpkt, xparam) == (KERMIT_XPKT_MINLEN - 1));

	kermit_xlen_set(xpkt, KERMIT_XPKT_MAXLEN);
	zabort(kermit_sum_offset_get(xpkt, xparam) == (KERMIT_XPKT_MAXLEN - 1));

	kermit_blen_set(xpkt, KERMIT_BPKT_MINLEN);
	kermit_seq_set(xpkt, 0);
	kermit_type_set(xpkt, 'Y');
	sumret[0] = 62;
	kermit_sum_set(xpkt, xparam, sumret);
	zabort(kermit_sum_get(xpkt, xparam, sumret) == 1);
	zabort(sumret[0] == 62);
	zabort(kermit_sum_chk(xpkt, xparam) == 1);

	void kermit_packet_dump(int8_t *pkt, int8_t *param);
	zabort(kermit_bpkt_make(xpkt, xparam, 0, 'Y', NULL, 0) == 0);
	zabort(kermit_sum_chk(xpkt, xparam) == 1);
	//kermit_packet_dump(xpkt, xparam);
	zabort(kermit_bpkt_make(xpkt, xparam, 1, 'Y', NULL, 0) == 0);
	zabort(kermit_sum_chk(xpkt, xparam) == 1);
	//kermit_packet_dump(xpkt, xparam);
	zabort(kermit_bpkt_make(xpkt, xparam, 63, 'N', NULL, 0) == 0);
	zabort(kermit_sum_chk(xpkt, xparam) == 1);
	//kermit_packet_dump(xpkt, xparam);
	zabort(kermit_bpkt_make(xpkt, xparam, 0, 'S', xparam, KERMIT_EPARAM_SIZE)
			== KERMIT_EPARAM_SIZE);
	zabort(kermit_sum_chk(xpkt, xparam) == 1);
	//kermit_packet_dump(xpkt, xparam);

	int8_t databuf[KERMIT_XPKT_MAXLEN];
	int32_t test_count = (32 * 1024 * 1024);
	int16_t i;
	srand(time(NULL));
	while(test_count > 0) {
		for (i = 0; i < KERMIT_XPKT_MAXLEN; i++) {
			databuf[i] = rand();
		}
		kermit_bpkt_make(xpkt, xparam, 0, 'D',
			databuf, rand() % KERMIT_XPKT_MAXLEN);
		zabort(kermit_sum_chk(xpkt, xparam) == 1);
		kermit_packet_dump(xpkt, xparam);
		test_count--;
	}
}

#include <stdio.h>

void kermit_packet_dump(int8_t *pkt, int8_t *param) {
	printf("LENGTH: %d ", kermit_len_get(pkt)); 
	printf("SUM: %s", kermit_sum_chk(pkt, param) ? "OK" : "FAIL");
	printf("\n\r");

	int16_t i;

	int qctl = 0;
	int qbin = 0;
	if (kermit_qctl_valid(param)) { qctl = kermit_qctl_get(param); }
	if (kermit_qbin_valid(param)) { qbin = kermit_qbin_get(param); }

	if (qctl && qbin) {
		for (i = 0; i < kermit_len_get(pkt); i++) {
			printf("%c", pkt[i]);
		}
		printf("\n\r");
	}
	for (i = 0; i < kermit_len_get(pkt); i++) {
		printf("%02X", pkt[i]);
	}
	printf("\n\r");
}

void kermit_encode_table_dump(int8_t *param) {
	int16_t i;
	int8_t id;
	int8_t enc[KERMIT_ENC_MAXSIZE];
	int ret, retd;
	int qctl = 0;
	int qbin = 0;
	if (kermit_qctl_valid(param)) { qctl = kermit_qctl_get(param); }
	if (kermit_qbin_valid(param)) { qbin = kermit_qbin_get(param); }
	
	printf("QCTL %02X QBIN %02X\n\r", qctl, qbin);
	for (i = 0; i < 0x100; i++) {
		enc[0] = enc[1] = enc[2] = 0;
		ret = kermit_data_encode(param, i, enc);
		retd = kermit_data_decode(param, enc, &id);
		printf("0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, ",
				 i, ret,
				enc[0] & 0xFF,
				enc[1] & 0xFF,
				enc[2] & 0xFF);
		if (qctl && qbin) {
			printf("\\\\ %c%c%c", enc[0], enc[1], enc[2]);
		}
		printf("\n\r");
		if (((id & 0xFF) != i) || (retd != ret)) {
			printf("fatal: check failed %02X\n\r", id);
			exit(EXIT_FAILURE);
		}
	}
}
