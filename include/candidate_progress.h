/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_CANDIDATE_PROGRESS_H
#define HC_CANDIDATE_PROGRESS_H

int  candidate_progress_init    (hashcat_ctx_t *hashcat_ctx, const kernel_rule_t *rules, const u32 rules_cnt);
void candidate_progress_destroy (hashcat_ctx_t *hashcat_ctx);

bool candidate_progress_enabled (const hashcat_ctx_t *hashcat_ctx);

u32  candidate_progress_rules_cnt    (const hashcat_ctx_t *hashcat_ctx);
u32  candidate_progress_rule_all_pos (const hashcat_ctx_t *hashcat_ctx, const u32 rule_pos);

int  candidate_progress_begin_pass (hashcat_ctx_t *hashcat_ctx, const u32 rule_all_pos);
bool candidate_progress_next_window (hashcat_ctx_t *hashcat_ctx, u64 *window_start, u64 *window_end);
void candidate_progress_end_pass    (hashcat_ctx_t *hashcat_ctx);

void candidate_progress_mark_batch  (hashcat_ctx_t *hashcat_ctx, const u64 words_off, const u64 words_fin, const u64 candidates);
void candidate_progress_print_stats (hashcat_ctx_t *hashcat_ctx);

#endif // HC_CANDIDATE_PROGRESS_H
