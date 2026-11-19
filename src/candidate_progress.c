/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "locking.h"
#include "thread.h"
#include "event.h"
#include "folder.h"
#include "filehandling.h"
#include "path.h"
#include "paw64.h"
#include "shared.h"
#include "rp.h"
#include "feed.h"
#include "candidate_progress.h"

#include <dirent.h>
#include <time.h>

#define CP_FORMAT "HCP1"

typedef struct cp_rule
{
  char id[33];
  u32  all_pos;

} cp_rule_t;

typedef struct cp_rule_entry
{
  char id[33];
  u32  all_pos;

} cp_rule_entry_t;

typedef struct cp_record
{
  char id[33];
  u64  seq;
  u64  start;
  u64  end;
  bool current;

} cp_record_t;

typedef struct cp_gap
{
  u64 start;
  u64 end;

} cp_gap_t;

typedef struct cp_records
{
  cp_record_t *buf;
  u32          cnt;
  u32          avail;

} cp_records_t;

typedef struct cp_hash_ctx
{
  paw64_ctx_t a;
  paw64_ctx_t b;

} cp_hash_ctx_t;

static void cp_hash_init (cp_hash_ctx_t *ctx)
{
  paw64_init (&ctx->a, 0x3141592653589793ULL);
  paw64_init (&ctx->b, 0x2718281828459045ULL);
}

static void cp_hash_update (cp_hash_ctx_t *ctx, const void *data, const size_t len)
{
  paw64_update (&ctx->a, data, len);
  paw64_update (&ctx->b, data, len);
}

static void cp_hash_hex (cp_hash_ctx_t *ctx, char out[33])
{
  const u64 a = paw64_final (&ctx->a);
  const u64 b = paw64_final (&ctx->b);

  snprintf (out, 33, "%016" PRIx64 "%016" PRIx64, a, b);

  out[32] = 0;
}

static void cp_rule_id (const kernel_rule_t *rule, char out[33])
{
  u8 rule_buf[RP_RULE_SIZE];

  memset (rule_buf, 0, sizeof (rule_buf));

  const int rule_len = kernel_rule_to_cpu_rule ((char *) rule_buf, (kernel_rule_t *) rule);

  cp_hash_ctx_t ctx;

  cp_hash_init (&ctx);

  if (rule_len >= 0)
  {
    cp_hash_update (&ctx, rule_buf, (size_t) rule_len);
  }
  else
  {
    cp_hash_update (&ctx, rule->cmds, sizeof (rule->cmds));
  }

  cp_hash_hex (&ctx, out);
}

static void cp_string (cp_hash_ctx_t *ctx, const char *str)
{
  if (str == NULL)
  {
    const u32 zero = 0;

    cp_hash_update (ctx, &zero, sizeof (zero));

    return;
  }

  cp_hash_update (ctx, str, strlen (str) + 1);
}

static void cp_file_hash (cp_hash_ctx_t *ctx, const char *path)
{
  if (hc_path_is_file (path) == false) return;

  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) return;

  u8 buf[65536];

  while (true)
  {
    const size_t nread = hc_fread (buf, 1, sizeof (buf), &fp);

    if (nread == 0) break;
    if (nread == (size_t) -1) break;

    cp_hash_update (ctx, buf, nread);
  }

  hc_fclose (&fp);
}

static void cp_path_hash (cp_hash_ctx_t *ctx, const char *path)
{
  if (hc_path_is_file (path) == true)
  {
    cp_file_hash (ctx, path);

    return;
  }

  if (hc_path_is_directory (path) == false) return;

  char **files = scan_directory (path);

  if (files == NULL) return;

  u32 files_cnt = 0;

  while (files[files_cnt] != NULL) files_cnt++;

  qsort (files, files_cnt, sizeof (char *), sort_by_stringptr);

  for (u32 i = 0; i < files_cnt; i++)
  {
    cp_string (ctx, files[i]);
    cp_path_hash (ctx, files[i]);

    hcfree (files[i]);
  }

  hcfree (files);
}

static void cp_source_id (hashcat_ctx_t *hashcat_ctx, char out[33])
{
  const generic_ctx_t  *generic_ctx  = &hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE];
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  cp_hash_ctx_t ctx;

  cp_hash_init (&ctx);

  cp_string (&ctx, "hashcat candidate progress source 1");

  cp_hash_update (&ctx, &generic_ctx->global_ctx.source_ident, sizeof (generic_ctx->global_ctx.source_ident));

  cp_hash_update (&ctx, &user_options->hex_wordlist, sizeof (user_options->hex_wordlist));
  cp_hash_update (&ctx, &user_options->wordlist_autohex, sizeof (user_options->wordlist_autohex));

  cp_string (&ctx, user_options->encoding_from);
  cp_string (&ctx, user_options->encoding_to);
  cp_string (&ctx, user_options->rule_buf_l);

  for (int i = 0; i < user_options_extra->hc_workc; i++)
  {
    const char *path = user_options_extra->hc_workv[i];

    cp_string (&ctx, path);
    cp_path_hash (&ctx, path);
  }

  for (u32 i = 0; i < straight_ctx->dicts_cnt; i++)
  {
    cp_string (&ctx, straight_ctx->dicts[i]);
    cp_path_hash (&ctx, straight_ctx->dicts[i]);
  }

  cp_hash_hex (&ctx, out);
}

static void cp_run_id (hashcat_ctx_t *hashcat_ctx, char out[33])
{
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  cp_hash_ctx_t ctx;

  cp_hash_init (&ctx);

  cp_string (&ctx, "hashcat candidate progress run 1");

  cp_hash_update (&ctx, &user_options->hash_mode, sizeof (user_options->hash_mode));
  cp_hash_update (&ctx, &user_options->attack_mode, sizeof (user_options->attack_mode));
  cp_hash_update (&ctx, hashes->digests_buf, (size_t) hashes->digests_cnt * hashconfig->dgst_size);

  for (u32 i = 0; i < hashes->salts_cnt; i++)
  {
    const salt_t *salt = &hashes->salts_buf[i];

    cp_hash_update (&ctx, &salt->salt_iter, sizeof (salt->salt_iter));
    cp_hash_update (&ctx, &salt->salt_len,  sizeof (salt->salt_len));
    cp_hash_update (&ctx,  salt->salt_buf,  sizeof (salt->salt_buf));
  }

  cp_hash_update (&ctx, hashcat_ctx->candidate_progress_ctx->source_id, 32);

  cp_hash_hex (&ctx, out);
}

static void cp_remove_tree (const char *path)
{
  if (hc_path_is_directory (path) == false)
  {
    unlink (path);

    return;
  }

  DIR *dir = opendir (path);

  if (dir == NULL) return;

  struct dirent *entry = NULL;

  while ((entry = readdir (dir)) != NULL)
  {
    if (entry->d_name[0] == '.') continue;

    char *child = NULL;

    hc_asprintf (&child, "%s/%s", path, entry->d_name);

    cp_remove_tree (child);

    hcfree (child);
  }

  closedir (dir);

  rmdir (path);
}

static void cp_records_add (cp_records_t *records, const char *id, const u64 seq, const u64 start, const u64 end, const bool current)
{
  if (start >= end) return;

  if (records->cnt == records->avail)
  {
    const u32 avail_old = records->avail;

    records->avail += 1024;

    records->buf = (cp_record_t *) hcrealloc (records->buf, avail_old * sizeof (cp_record_t), 1024 * sizeof (cp_record_t));
  }

  cp_record_t *record = &records->buf[records->cnt];

  snprintf (record->id, sizeof (record->id), "%s", id);

  record->seq   = seq;
  record->start = start;
  record->end   = end;
  record->current = current;

  records->cnt++;
}

static bool cp_file_bad (hashcat_ctx_t *hashcat_ctx, const char *path, const char *why)
{
  event_log_warning (hashcat_ctx, "Candidate progress: %s: %s", path, why);
  event_log_warning (hashcat_ctx, "Candidate progress: the damaged records will be discarded and the run starts from scratch.");
  event_log_warning (hashcat_ctx, NULL);

  unlink (path);

  return false;
}

static bool cp_file_load (hashcat_ctx_t *hashcat_ctx, const char *path, cp_records_t *records)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) return cp_file_bad (hashcat_ctx, path, hc_fopen_strerror ());

  char line[1024];

  bool header = false;

  while (hc_fgets (line, sizeof (line), &fp) != NULL)
  {
    size_t line_len = strlen (line);

    while ((line_len > 0) && ((line[line_len - 1] == '\n') || (line[line_len - 1] == '\r')))
    {
      line_len--;

      line[line_len] = 0;
    }

    if (line[0] == 0) continue;

    if (header == false)
    {
      char run_id[33]    = { 0 };
      char source_id[33] = { 0 };
      char ruleset[33]   = { 0 };

      if (sscanf (line, CP_FORMAT " run=%32s source=%32s ruleset=%32s", run_id, source_id, ruleset) != 3)
      {
        hc_fclose (&fp);

        return cp_file_bad (hashcat_ctx, path, "invalid header");
      }

      if ((strcmp (run_id, cp->run_id) != 0) || (strcmp (source_id, cp->source_id) != 0))
      {
        hc_fclose (&fp);

        return cp_file_bad (hashcat_ctx, path, "records belong to another source or target");
      }

      char path_copy[2048];

      snprintf (path_copy, sizeof (path_copy), "%s", path);

      char *slash = strrchr (path_copy, '/');

      if (slash == NULL)
      {
        hc_fclose (&fp);

        return cp_file_bad (hashcat_ctx, path, "record path has no rule-set directory");
      }

      slash[0] = 0;

      slash = strrchr (path_copy, '/');

      const char *dir = (slash == NULL) ? path_copy : (slash + 1);

      if (strcmp (dir, ruleset) != 0)
      {
        hc_fclose (&fp);

        return cp_file_bad (hashcat_ctx, path, "records do not belong to this rule-set directory");
      }

      header = true;

      continue;
    }

    if (line[0] != 'T')
    {
      hc_fclose (&fp);

      return cp_file_bad (hashcat_ctx, path, "unknown record type");
    }

    char *last = strrchr (line, ' ');

    if (last == NULL)
    {
      hc_fclose (&fp);

      return cp_file_bad (hashcat_ctx, path, "record has no checksum");
    }

    char checksum_buf[17] = { 0 };

    snprintf (checksum_buf, sizeof (checksum_buf), "%s", last + 1);

    last[0] = 0;

    u64 checksum = 0;

    if (sscanf (checksum_buf, "%" SCNx64, &checksum) != 1)
    {
      hc_fclose (&fp);

      return cp_file_bad (hashcat_ctx, path, "record checksum is not a number");
    }

    if (paw64 (line, strlen (line), 0) != checksum)
    {
      hc_fclose (&fp);

      return cp_file_bad (hashcat_ctx, path, "record checksum mismatch");
    }

    u64 seq = 0;
    u64 start = 0;
    u64 end = 0;
    u64 count = 0;

    char id[33] = { 0 };

    u32 dict_pos = 0;

    if (sscanf (line, "T %" SCNu64 " %32s %u %" SCNu64 " %" SCNu64 " %" SCNu64, &seq, id, &dict_pos, &start, &end, &count) != 6)
    {
      hc_fclose (&fp);

      return cp_file_bad (hashcat_ctx, path, "invalid record");
    }

    if (dict_pos != 0)
    {
      hc_fclose (&fp);

      return cp_file_bad (hashcat_ctx, path, "record names another dictionary");
    }

    if ((start >= end) || (count == 0) || (count > (end - start)))
    {
      hc_fclose (&fp);

      return cp_file_bad (hashcat_ctx, path, "record has an empty range");
    }

    cp_records_add (records, id, seq, start, end, false);

    if (seq >= cp->next_seq) cp->next_seq = seq + 1;
  }

  hc_fclose (&fp);

  if (header == false) return cp_file_bad (hashcat_ctx, path, "empty file");

  return true;
}

static bool cp_records_load (hashcat_ctx_t *hashcat_ctx, cp_records_t *records)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  DIR *root = opendir (cp->run_dir);

  if (root == NULL) return true;

  bool ok = true;

  struct dirent *entry = NULL;

  while ((entry = readdir (root)) != NULL)
  {
    if (entry->d_name[0] == '.') continue;

    char *rule_dir = NULL;

    hc_asprintf (&rule_dir, "%s/%s", cp->run_dir, entry->d_name);

    if (hc_path_is_directory (rule_dir) == false)
    {
      hcfree (rule_dir);

      continue;
    }

    char **files = scan_directory (rule_dir);

    if (files != NULL)
    {
      for (u32 i = 0; files[i] != NULL; i++)
      {
        const size_t name_len = strlen (files[i]);

        if ((name_len < 4) || (strcmp (files[i] + name_len - 4, ".hcp") != 0))
        {
          hcfree (files[i]);

          continue;
        }

        if (cp_file_load (hashcat_ctx, files[i], records) == false) ok = false;

        hcfree (files[i]);
      }

      hcfree (files);
    }

    hcfree (rule_dir);

    if (ok == false) break;
  }

  closedir (root);

  if (ok == false)
  {
    hcfree (records->buf);

    records->buf   = NULL;
    records->cnt   = 0;
    records->avail = 0;

    cp_remove_tree (cp->run_dir);

    if (hc_mkdir_rec (cp->run_dir, 0700) == -1)
    {
      event_log_error (hashcat_ctx, "Candidate progress: cannot create %s", cp->run_dir);

      cp->enabled = false;
    }
  }

  return ok;
}

static void cp_rules_prune (hashcat_ctx_t *hashcat_ctx)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  DIR *root = opendir (cp->run_dir);

  if (root == NULL) return;

  struct dirent *entry = NULL;

  while ((entry = readdir (root)) != NULL)
  {
    if (entry->d_name[0] == '.') continue;
    if (strcmp (entry->d_name, cp->ruleset_id) == 0) continue;

    char *path = NULL;

    hc_asprintf (&path, "%s/%s", cp->run_dir, entry->d_name);

    if (hc_path_is_directory (path) == true)
    {
      cp_remove_tree (path);
    }

    hcfree (path);
  }

  closedir (root);
}

static int cp_rule_cmp (const void *a, const void *b)
{
  const cp_rule_entry_t *ra = (const cp_rule_entry_t *) a;
  const cp_rule_entry_t *rb = (const cp_rule_entry_t *) b;

  const int rc = strcmp (ra->id, rb->id);

  if (rc != 0) return rc;

  if (ra->all_pos < rb->all_pos) return -1;
  if (ra->all_pos > rb->all_pos) return  1;

  return 0;
}

static int cp_gap_cmp (const void *a, const void *b)
{
  const cp_gap_t *ga = (const cp_gap_t *) a;
  const cp_gap_t *gb = (const cp_gap_t *) b;

  if (ga->start < gb->start) return -1;
  if (ga->start > gb->start) return  1;

  return 0;
}

static int cp_records_rule (hashcat_ctx_t *hashcat_ctx, const char *id, cp_gap_t **out_gaps, u64 *out_covered)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  const cp_records_t *records = (const cp_records_t *) cp->records;

  const bool use_current = hashcat_ctx->user_options->candidate_dedup;

  cp_gap_t *covered = NULL;

  u32 covered_cnt = 0;

  for (u32 i = 0; i < records->cnt; i++)
  {
    const cp_record_t *record = &records->buf[i];

    if (strcmp (record->id, id) != 0) continue;
    if ((record->current == true) && (use_current == false)) continue;

    covered = (cp_gap_t *) hcrealloc (covered, covered_cnt * sizeof (cp_gap_t), sizeof (cp_gap_t));

    covered[covered_cnt].start = MIN (record->start, cp->base_words);
    covered[covered_cnt].end   = MIN (record->end,   cp->base_words);

    if (covered[covered_cnt].start < covered[covered_cnt].end) covered_cnt++;
  }

  if (covered_cnt == 0)
  {
    hcfree (covered);

    cp_gap_t *gaps = (cp_gap_t *) hcmalloc (sizeof (cp_gap_t));

    gaps[0].start = 0;
    gaps[0].end   = cp->base_words;

    *out_gaps    = gaps;
    *out_covered = 0;

    return 1;
  }

  qsort (covered, covered_cnt, sizeof (cp_gap_t), cp_gap_cmp);

  cp_gap_t *merged = NULL;

  u32 merged_cnt = 0;

  for (u32 i = 0; i < covered_cnt; i++)
  {
    if ((merged_cnt > 0) && (covered[i].start <= merged[merged_cnt - 1].end))
    {
      merged[merged_cnt - 1].end = MAX (merged[merged_cnt - 1].end, covered[i].end);

      continue;
    }

    merged = (cp_gap_t *) hcrealloc (merged, merged_cnt * sizeof (cp_gap_t), sizeof (cp_gap_t));

    merged[merged_cnt] = covered[i];

    merged_cnt++;
  }

  hcfree (covered);

  cp_gap_t *gaps = NULL;

  u32 gaps_cnt = 0;

  u64 at = 0;

  u64 total = 0;

  for (u32 i = 0; i < merged_cnt; i++)
  {
    if (merged[i].start > at)
    {
      gaps = (cp_gap_t *) hcrealloc (gaps, gaps_cnt * sizeof (cp_gap_t), sizeof (cp_gap_t));

      gaps[gaps_cnt].start = at;
      gaps[gaps_cnt].end   = merged[i].start;

      gaps_cnt++;
    }

    total += merged[i].end - merged[i].start;

    at = MAX (at, merged[i].end);
  }

  if (at < cp->base_words)
  {
    gaps = (cp_gap_t *) hcrealloc (gaps, gaps_cnt * sizeof (cp_gap_t), sizeof (cp_gap_t));

    gaps[gaps_cnt].start = at;
    gaps[gaps_cnt].end   = cp->base_words;

    gaps_cnt++;
  }

  hcfree (merged);

  *out_gaps    = gaps;
  *out_covered = total;

  return (int) gaps_cnt;
}

int candidate_progress_init (hashcat_ctx_t *hashcat_ctx, const kernel_rule_t *rules, const u32 rules_cnt)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  const user_options_t       *user_options        = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  const straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;

  if (user_options->candidate_progress == false) return 0;

  if (user_options_extra->attack_kern != ATTACK_KERN_STRAIGHT)
  {
    event_log_warning (hashcat_ctx, "Candidate progress: only a straight attack with rules is supported. The run continues without it.");
    event_log_warning (hashcat_ctx, NULL);

    return 0;
  }

  if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT) || (user_options->slow_candidates == true))
  {
    event_log_warning (hashcat_ctx, "Candidate progress: this attack builds candidates that a rule context cannot address. The run continues without it.");
    event_log_warning (hashcat_ctx, NULL);

    return 0;
  }

  if ((user_options_extra->base_source != BASE_SOURCE_FEED) && (straight_ctx->dicts_cnt != 1))
  {
    event_log_warning (hashcat_ctx, "Candidate progress: a run with several dictionaries has no single base range. The run continues without it.");
    event_log_warning (hashcat_ctx, NULL);

    return 0;
  }

  const u64 base_words = hashcat_ctx->generic_ctx[GENERIC_ROLE_BASE].keyspace;

  if ((base_words == 0) || (base_words == GENERIC_KEYSPACE_UNKNOWN))
  {
    event_log_warning (hashcat_ctx, "Candidate progress: the base source has no known keyspace. The run continues without it.");
    event_log_warning (hashcat_ctx, NULL);

    return 0;
  }

  cp->enabled    = true;
  cp->use_records = true;

  hc_thread_mutex_init (cp->mux_file);

  cp->mutex_inited = true;

  cp->base_words = base_words;

  cp_source_id (hashcat_ctx, cp->source_id);
  cp_run_id    (hashcat_ctx, cp->run_id);

  cp_hash_ctx_t ruleset_ctx;

  cp_hash_init (&ruleset_ctx);

  cp_string (&ruleset_ctx, "hashcat candidate progress ruleset 1");
  cp_hash_update (&ruleset_ctx, cp->source_id, 32);

  for (u32 i = 0; i < rules_cnt; i++)
  {
    char id[33];

    cp_rule_id (&rules[i], id);

    cp_hash_update (&ruleset_ctx, id, 32);
  }

  cp_hash_hex (&ruleset_ctx, cp->ruleset_id);

  hc_asprintf (&cp->root_dir, "%s/%s.candidate-progress", hashcat_ctx->folder_config->session_dir, user_options->session);
  hc_asprintf (&cp->run_dir,  "%s/%s", cp->root_dir, cp->run_id);

  if (hc_mkdir_rec (cp->run_dir, 0700) == -1)
  {
    event_log_error (hashcat_ctx, "Candidate progress: cannot create %s", cp->root_dir);

    cp->enabled = false;

    return 0;
  }

  cp_records_t *records = (cp_records_t *) hcmalloc (sizeof (cp_records_t));

  memset (records, 0, sizeof (cp_records_t));

  cp->records = records;

  if (cp_records_load (hashcat_ctx, records) == false) cp->use_records = false;

  if (user_options->candidate_progress_prune == true) cp_rules_prune (hashcat_ctx);

  cp_rule_t *rule_order = (cp_rule_t *) hcmalloc (rules_cnt * sizeof (cp_rule_t));

  u32 rule_order_cnt = 0;

  if (user_options->candidate_dedup == false)
  {
    for (u32 i = 0; i < rules_cnt; i++)
    {
      cp_rule_id (&rules[i], rule_order[rule_order_cnt].id);

      rule_order[rule_order_cnt].all_pos = i;

      rule_order_cnt++;
    }
  }
  else
  {
    cp_rule_entry_t *entries = (cp_rule_entry_t *) hcmalloc (rules_cnt * sizeof (cp_rule_entry_t));

    for (u32 i = 0; i < rules_cnt; i++)
    {
      cp_rule_id (&rules[i], entries[i].id);

      entries[i].all_pos = i;
    }

    qsort (entries, rules_cnt, sizeof (cp_rule_entry_t), cp_rule_cmp);

    bool *drop = (bool *) hccalloc (rules_cnt, sizeof (bool));

    for (u32 i = 1; i < rules_cnt; i++)
    {
      if (strcmp (entries[i].id, entries[i - 1].id) != 0) continue;

      drop[entries[i].all_pos] = true;
    }

    for (u32 i = 0; i < rules_cnt; i++)
    {
      if (drop[i] == true) continue;

      cp_rule_id (&rules[i], rule_order[rule_order_cnt].id);

      rule_order[rule_order_cnt].all_pos = i;

      rule_order_cnt++;
    }

    cp->dedup_skipped = (u64) (rules_cnt - rule_order_cnt) * base_words;

    hcfree (drop);
    hcfree (entries);
  }

  cp->rules     = rule_order;
  cp->rules_cnt = rule_order_cnt;

  u32 matching_rules = 0;

  for (u32 i = 0; i < rule_order_cnt; i++)
  {
    for (u32 j = 0; j < records->cnt; j++)
    {
      if (strcmp (rule_order[i].id, records->buf[j].id) != 0) continue;

      matching_rules++;

      break;
    }
  }

  if ((cp->use_records == true) && (records->cnt > 0) && (matching_rules == 0))
  {
    event_log_warning (hashcat_ctx, "Candidate progress: no recorded rule context is present in this rule set. Starting from scratch.");
    event_log_warning (hashcat_ctx, NULL);

    cp->use_records = false;
  }

  event_log_info (hashcat_ctx, "Candidate progress: source=%s ruleset=%s", cp->source_id, cp->ruleset_id);
  event_log_info (hashcat_ctx, "Candidate progress: %u rule contexts, %u selected, %u batch records loaded", rules_cnt, rule_order_cnt, records->cnt);

  if ((cp->use_records == true) && (records->cnt > 0))
  {
    event_log_info (hashcat_ctx, "Candidate progress: records are shared by rule context, so a larger or reordered rule set keeps every match.");
  }
  else
  {
    event_log_info (hashcat_ctx, "Candidate progress: no usable records for this run, starting from scratch.");
  }

  return 0;
}

void candidate_progress_destroy (hashcat_ctx_t *hashcat_ctx)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  cp_records_t *records = (cp_records_t *) cp->records;

  if (records != NULL)
  {
    hcfree (records->buf);
    hcfree (records);
  }

  hcfree (cp->gaps);
  hcfree (cp->rules);
  hcfree (cp->root_dir);
  hcfree (cp->run_dir);

  if (cp->mutex_inited == true) hc_thread_mutex_delete (cp->mux_file);

  memset (cp, 0, sizeof (candidate_progress_ctx_t));
}

bool candidate_progress_enabled (const hashcat_ctx_t *hashcat_ctx)
{
  return hashcat_ctx->candidate_progress_ctx->enabled;
}

u32 candidate_progress_rules_cnt (const hashcat_ctx_t *hashcat_ctx)
{
  return hashcat_ctx->candidate_progress_ctx->rules_cnt;
}

u32 candidate_progress_rule_all_pos (const hashcat_ctx_t *hashcat_ctx, const u32 rule_pos)
{
  const candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  const cp_rule_t *rules = (const cp_rule_t *) cp->rules;

  if (rule_pos >= cp->rules_cnt) return 0;

  return rules[rule_pos].all_pos;
}

int candidate_progress_begin_pass (hashcat_ctx_t *hashcat_ctx, const u32 rule_all_pos)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  const cp_rule_t *rules = (const cp_rule_t *) cp->rules;

  u32 found = cp->rules_cnt;

  for (u32 i = 0; i < cp->rules_cnt; i++)
  {
    if (rules[i].all_pos != rule_all_pos) continue;

    found = i;

    break;
  }

  if (found == cp->rules_cnt) return -1;

  snprintf (cp->current_rule_id, sizeof (cp->current_rule_id), "%s", rules[found].id);

  u64 covered = 0;

  cp_gap_t *gaps = NULL;

  int gaps_cnt = 0;

  if (cp->use_records == true)
  {
    gaps_cnt = cp_records_rule (hashcat_ctx, cp->current_rule_id, &gaps, &covered);

    if (gaps_cnt < 0)
    {
      hcfree (gaps);

      return -1;
    }
  }
  else
  {
    gaps = (cp_gap_t *) hcmalloc (sizeof (cp_gap_t));

    gaps[0].start = 0;
    gaps[0].end   = cp->base_words;

    gaps_cnt = 1;
  }

  cp->tried_before += covered;
  cp->skipped      += covered;

  cp->gaps     = gaps;
  cp->gaps_cnt = (u32) gaps_cnt;
  cp->gaps_pos = 0;

  return 0;
}

bool candidate_progress_next_window (hashcat_ctx_t *hashcat_ctx, u64 *window_start, u64 *window_end)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  if (cp->gaps_pos >= cp->gaps_cnt)
  {
    cp->window_active = false;

    hcfree (cp->gaps);

    cp->gaps    = NULL;
    cp->gaps_cnt = 0;
    cp->gaps_pos = 0;

    return false;
  }

  const cp_gap_t *gaps = (const cp_gap_t *) cp->gaps;

  window_start[0] = gaps[cp->gaps_pos].start;
  window_end[0]   = gaps[cp->gaps_pos].end;

  cp->window_active = true;
  cp->window_start  = window_start[0];
  cp->window_end    = window_end[0];

  cp->gaps_pos++;

  return true;
}

void candidate_progress_end_pass (hashcat_ctx_t *hashcat_ctx)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  cp->window_active = false;

  hcfree (cp->gaps);

  cp->gaps     = NULL;
  cp->gaps_cnt = 0;
  cp->gaps_pos = 0;
}

static int cp_file_append (hashcat_ctx_t *hashcat_ctx, const char *path, const char *line)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  HCFILE fp;

  if (hc_fopen (&fp, path, "ab") == false)
  {
    event_log_error (hashcat_ctx, "Candidate progress: %s: %s", path, hc_fopen_strerror ());

    return -1;
  }

  struct stat st;

  if ((hc_fstat (&fp, &st) == 0) && (st.st_size == 0))
  {
    char month[8];

    time_t now = time (NULL);

    struct tm tm;

    if (localtime_r (&now, &tm) == NULL)
    {
      hc_fclose (&fp);

      return -1;
    }

    if (strftime (month, sizeof (month), "%Y%m", &tm) == 0)
    {
      hc_fclose (&fp);

      return -1;
    }

    if (hc_fprintf (&fp, CP_FORMAT " run=%s source=%s ruleset=%s month=%s\n", cp->run_id, cp->source_id, cp->ruleset_id, month) < 0)
    {
      hc_fclose (&fp);

      return -1;
    }
  }

  if (hc_fprintf (&fp, "%s\n", line) < 0)
  {
    hc_fclose (&fp);

    return -1;
  }

  hc_fflush (&fp);

  hc_fclose (&fp);

  return 0;
}

void candidate_progress_mark_batch (hashcat_ctx_t *hashcat_ctx, const u64 words_off, const u64 words_fin, const u64 candidates)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  if (cp->enabled == false) return;
  if (cp->window_active == false) return;

  const u64 start = MAX (words_off, cp->window_start);
  const u64 end   = MIN (words_fin, cp->window_end);

  if (start >= end) return;

  hc_thread_mutex_lock (cp->mux_file);

  cp_records_t *records = (cp_records_t *) cp->records;

  char record[512];

  const u64 seq = cp->next_seq++;

  cp_records_add (records, cp->current_rule_id, seq, start, end, true);

  const int record_len = snprintf (record, sizeof (record), "T %" PRIu64 " %s %u %" PRIu64 " %" PRIu64 " %" PRIu64, seq, cp->current_rule_id, 0, start, end, candidates);

  if (record_len < 0)
  {
    hc_thread_mutex_unlock (cp->mux_file);

    return;
  }

  char line[1024];

  snprintf (line, sizeof (line), "%s %016" PRIx64, record, paw64 (record, (size_t) record_len, 0));

  char rule_dir[1024];

  char month[8];

  time_t now = time (NULL);

  struct tm tm;

  if (localtime_r (&now, &tm) == NULL)
  {
    hc_thread_mutex_unlock (cp->mux_file);

    return;
  }

  if (strftime (month, sizeof (month), "%Y%m", &tm) == 0)
  {
    hc_thread_mutex_unlock (cp->mux_file);

    return;
  }

  snprintf (rule_dir, sizeof (rule_dir), "%s/%s", cp->run_dir, cp->ruleset_id);

  if (hc_mkdir_rec (rule_dir, 0700) == -1)
  {
    hc_thread_mutex_unlock (cp->mux_file);

    return;
  }

  char path[1200];

  snprintf (path, sizeof (path), "%s/%s.hcp", rule_dir, month);

  cp_file_append (hashcat_ctx, path, line);

  cp->new_tried += candidates;

  hc_thread_mutex_unlock (cp->mux_file);
}

void candidate_progress_print_stats (hashcat_ctx_t *hashcat_ctx)
{
  candidate_progress_ctx_t *cp = hashcat_ctx->candidate_progress_ctx;

  if (cp->enabled == false) return;
  if (cp->stats_printed == true) return;

  cp->stats_printed = true;

  event_log_info (hashcat_ctx, "Candidate progress: tried-before=%" PRIu64 " skipped=%" PRIu64 " new=%" PRIu64 " dedup-skipped=%" PRIu64, cp->tried_before, cp->skipped, cp->new_tried, cp->dedup_skipped);
}
