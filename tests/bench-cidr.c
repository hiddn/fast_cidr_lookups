/* bench-cidr.c benchmarks CIDR lookup libraries.
 *
 * In IRC, this corresponds to K-line or G-line entries.  It has the
 * same semantics as "longest prefix match" routing lookups in more
 * generic computer science.  To be generic, these comments talk about
 * "entries" in a "table".  This assumes a single IPv6 table, with IPv4
 * entries using IPv4-mapped IPv6 address formats.
 *
 * The benchmark has five phases:
 *
 * - Planning, where it generates a set of entries for the run.
 * - Loading, where a large set of entries are loaded in a batch.
 *   For ircu, this corresponds to a server receiving an initial burst
 *   from the network.
 * - Updates, where entries are inserted or removed.
 * - Lookups of addresses, where only some addresses have entries.
 * - Reloading, where the initial load is repeated.  For ircu, this
 *   corresponds to reconnecting after a net split.
 *
 * Each phase is timed, and malloc statistics are reported if we have
 * support code to do that on the current OS / libc.
 *
 * Parameters for a randomly generated plan are as follows:
 * - For each of v4 and v6, several integers:
 *   - n_mask, the number of IP mask entries to generate.
 *   - n_full, the number of full-IP entries to generate.
 *   - n_miss, the number of non-matching IPs to query.
 *   - w[N], the relative likelihood of an N-bit mask being generated;
 *     for IPv4, w[1..17] indicates N from 8 to 24 inclusive;
 *     for IPv6, w[1..19] indicates 16, 32, 48, 64, 49 to 63 inclusive.
 *     The sum of w[N] must be less than 2**64.
 * - p_load, the probability of an entry being initially active,
 *   multiplied by 2**32.
 * Lookups randomly pick one of the n_full+n_miss full-IP entries.
 *
 * Random entries can be a prefix or suffix of another entry, so that
 * we check longest prefix matching, but cannot exactly match IP+masklen.
 * Random IPv4 addresses are evenly distributed over 1.0.0.0 to 223.255.255.255.
 * Random IPv6 addresses are evenly distributed over 2000::/4.
 *
 * Planning generates the IP masks and full-IP entries first (which is
 * easy because the IP masks can arbitrarily overlap other masks and
 * full-IP entries), then the non-matching IPs (which must know the
 * entries to check whether a random IP does not match any entry).
 *
 * The library being benchmarked needs to provide three operations:
 * - init()
 * - map(entry, voidp), where !voidp means to remove the entry
 * - lookup(entry) -> voidp
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#if defined(CIDR_LOOKUPS_API)
# include "../include/cidr_lookups.h"
#else
# include "../include/irc_stuff.h"
#endif

#if defined(__DARWIN_C_LEVEL)
# define HAS_MSTATS
# include <malloc/malloc.h>
#endif

/** Representation of a single entry in the table. */
struct entry {
	/* IPv6 address. */
	struct irc_in_addr addr;

	/** Number of bits used to match the address.
	 * 0 means this entry is a non-matching IP.
	 * 128 means this entry is a full-IP entry.
	 * 1..127 means this entry is a CIDR mask entry; the LSBs of
	 * addr.in6_16[] must be cleared.
	 */
	uint8_t nbits;

	/** If nbits != 0, active indicates whether the entry is active.
	 * If nbits == 0, active is not used.
	 */
	uint8_t active;

	/** Whether this entry was initially active. */
	uint8_t orig_active;

	/** Padding to make sizeof(entry) a nice number. */
	uint8_t pad[1];

	/* Address in text format.
	 * Longest possible content:
	 * aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/127\0
	 * 01234567890123456789012345678901234567890123
	 * 0         1         2         3         4
	 */
	char text[44];
};

uint64_t v4_n_mask = 1000, v4_n_full = 2000, v4_n_miss = 40000, v4_n_total;
uint64_t v6_n_mask = 1000, v6_n_full = 2000, v6_n_miss = 40000, v6_n_total;
uint64_t n_mask, n_full, n_miss, n_total;
/* w[0] will be set to the sum of w[1..n]. */
uint64_t v4_w[18] = { 0, 1, 1, 1, 1, 1, 1, 1, 2, 50, /* _, 8 .. 16 */
	5, 5, 5, 5, 5, 5, 5, 25 /* 17 .. 24 */
};
uint64_t v6_w[20] = { 0, 5, 5, 100, 500, 25, /* _, 16, 32, 48, 64, */
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 /* 49 .. 63 */
};
uint64_t p_load;
struct entry *table;
int verbose;
#if defined(CIDR_LOOKUPS_API)
cidr_root_node *cidr_root;
#else
# error "No (supported) CIDR API was selected"
#endif

/* ******************** */
/* forward declarations */
/* ******************** */

void plan_sort(uint64_t base, uint64_t count);

/* ******************************* */
/* implementation adaptation layer */
/* ******************************* */

void table_init()
{
#if defined(CIDR_LOOKUPS_API)
	cidr_root = cidr_new_tree();
#endif
}

void table_map(const struct entry *entry, void *value)
{
#if defined(CIDR_LOOKUPS_API)
	if (value)
	{
		cidr_add_node(cidr_root, entry->text, value);
	}
	else
	{
		cidr_rem_node_by_cidr(cidr_root, entry->text);
	}
#endif
}

void *table_lookup(const struct entry *entry)
{
#if defined(CIDR_LOOKUPS_API)
	cidr_node *node = cidr_search_best(cidr_root, entry->text);
	return node ? node->data : NULL;
#endif
}

void table_load(const char *filename)
{
	struct entry *ee;
	FILE *f;
	size_t t_alloc = 0, t_used = 0, ii, hist[130];
	char buf[1024], *at;
	int res;

	/* Open the file. */
	f = fopen(filename, "rt");
	if (!f)
	{
		fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize our histogram and "hit" counts. */
	for (ii = 0; ii < 130; ++ii) hist[ii] = 0;
	v4_n_mask = 0;
	v4_n_full = 0;
	v6_n_mask = 0;
	v6_n_full = 0;

	/* Read all the lines we can from the file. */
	while (fgets(buf, sizeof buf, f))
	{
		/* Assume that the mask we want is after the first @, until
		 * the next whitespace or EOL.
		 */
		at = strchr(buf, '@');
		if (!at) continue;
		for (ii = 0, ++at; at[ii] != '\0'; ++ii)
		{
			if (isspace(at[ii]))
			{
				at[ii] = '\0';
				break;
			}
		}

		/* Make sure there is room for this entry in our table. */
		if (t_used >= t_alloc)
		{
			t_alloc = t_alloc ? (t_alloc << 1) : 512;
			table = realloc(table, t_alloc * sizeof table[0]);
			if (!table)
			{
				fprintf(stderr, "Unable to allocate %zu entries: %s",
					t_alloc, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		ee = &table[t_used];

		/* Parse the mask. */
		res = ipmask_parse(at, &ee->addr, &ee->nbits);
		if (!res)
		{
			if (verbose > 0) printf("unparsed: %s\n", at);
			++hist[129];
			continue;
		}

		/* Update statistics. */
		++hist[ee->nbits];
		if (irc_in_addr_is_ipv4(&ee->addr))
		{
			if (ee->nbits < 128) ++v4_n_mask;
			else ++v4_n_full;
		}
		else
		{
			if (ee->nbits < 128) ++v6_n_mask;
			else ++v6_n_full;
		}
		++t_used;
	}

	/* Should we print our histogram? */
	if (verbose > 0)
	{
		printf("nbits,count\n");
		for (ii = 0; ii < 130; ++ii)
		{
			if (hist[ii] != 0)
			{
				printf("%zu,%zu\n", ii, hist[ii]);
			}
		}
	}

	/* Make space to add the "miss" entries.
	 * Sort IPv4 < IPv6, then move the IPv6 entries out.
	 * This puts those entries in the same order they would be generated
	 * by plan_random().
	 */
	plan_sort(0, t_used);
	v4_n_total = v4_n_mask + v4_n_full + v4_n_miss;
	memmove(&table[v4_n_total], &table[v4_n_mask + v4_n_full],
		(v6_n_mask + v6_n_full) * sizeof table[0]);

	/* Exit. */
	fclose(f);
}

/* ****************************** */
/* benchmarking support functions */
/* ****************************** */

#define BENCH_CLOCK CLOCK_REALTIME
struct timespec b_started;
struct itimerval b_interval;
volatile sig_atomic_t b_sig_flag;
#if defined(HAS_MSTATS)
struct mstats b_m_stats;
#endif

void b_vtalrm(int sig)
{
	b_sig_flag = 1;
	(void)sig;
}

void bench_start(void)
{
	struct sigaction sa;

	/* Collect baseline malloc statistics. */
#if defined(HAS_MSTATS)
	b_m_stats = mstats();
#endif

	/* Call b_vtalrm() when the virtual itimer expires. */
	memset(&sa, 0, sizeof sa);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = b_vtalrm;
	sigaction(SIGVTALRM, &sa, NULL);

	/* Final setup for benchmarking. */
	b_sig_flag = 0;
	setitimer(ITIMER_VIRTUAL, &b_interval, NULL);
	clock_gettime(BENCH_CLOCK, &b_started);
}

void bench_report(const char *phase, uint64_t count)
{
#if defined(HAS_MSTATS)
	struct mstats m_stats;
#endif
	struct timespec now;
	double ns_per;

	/* Measure elapsed time. */
	clock_gettime(BENCH_CLOCK, &now);
	if (now.tv_nsec < b_started.tv_nsec)
	{
		now.tv_sec -= 1;
		now.tv_nsec += 1000000000;
	}
	now.tv_sec -= b_started.tv_sec;
	now.tv_nsec -= b_started.tv_nsec;
	ns_per = (now.tv_sec * 1e9 + now.tv_nsec) / count;
	printf("%s: %llu in %lu.%09lu s = %g ns/item\n",
		phase, (long long unsigned)count, now.tv_sec, now.tv_nsec, ns_per);

	/* Collect malloc statistics. */
#if defined(HAS_MSTATS)
	m_stats = mstats();
	printf(" ... %zu bytes_total, %zu chunks_used, %zu bytes_used, %zu chunks_free, %zd bytes_free\n",
		m_stats.bytes_total - b_m_stats.bytes_total,
		m_stats.chunks_used - b_m_stats.chunks_used,
		m_stats.bytes_used - b_m_stats.bytes_used,
		m_stats.chunks_free - b_m_stats.chunks_free,
		m_stats.bytes_free - b_m_stats.bytes_free);
	memcpy(&b_m_stats, &m_stats, sizeof b_m_stats);
#endif

	/* Restart things for the next phase. */
	b_sig_flag = 0;
	setitimer(ITIMER_VIRTUAL, &b_interval, NULL);
	clock_gettime(BENCH_CLOCK, &b_started);
}

/* ******************************* */
/* pseudo-random number generation */
/* ******************************* */

/* PCG64 DXSM, based on https://github.com/fanf2/pcg-dxsm . */

struct {
	__uint128_t state, inc;
} pcg;

uint64_t prng_word(void)
{
	const uint64_t mul = 15750249268501108917ULL;
	__uint128_t state = pcg.state;
	uint64_t hi, lo;
	pcg.state = state * mul + pcg.inc;
	hi = state >> 64;
	lo = state | 1;
	hi ^= hi >> 32;
	hi *= mul;
	hi ^= hi >> 48;
	hi *= lo;
	return hi;
}

void prng_seed(uint64_t seed)
{
	pcg.inc =
		((__uint128_t)6364136223846793005ULL << 64 |
		 (__uint128_t)1442695040888963407ULL);
	pcg.state = pcg.inc + seed;
	(void)prng_word();
}

uint64_t b_prng[4096];
unsigned int b_prng_bits;

uint64_t prng_bits(unsigned int nbits)
{
	uint64_t res = 0;
	unsigned int avail;

	if (nbits < 1 || nbits > 63)
	{
		fprintf(stderr, "prng_bits() got invalid nbits=%u\n", nbits);
		abort();
	}
	if (b_prng_bits < nbits)
	{
		for (avail = 0; avail < 4096; ++avail)
		{
			b_prng[avail] = prng_word();
		}
	}

	/* Is there a partial word? */
	if ((avail = (b_prng_bits & 63)) != 0)
	{
		res = b_prng[b_prng_bits / 64] >> (63 - avail);
		if (avail > nbits) avail = nbits;/* use only some of the bits */
		res &= ((uint64_t)1 << avail) - 1;
		b_prng_bits -= avail;
	}

	/* Grab any further bits we need. */
	if (nbits > 0)
	{
		b_prng_bits -= nbits;
		res <<= nbits;
		res |= b_prng[b_prng_bits / 64] & ((1u << nbits) - 1);
	}

	return res;
}

uint64_t prng_mod(uint64_t limit)
{
	__uint128_t sample = prng_word() * (__uint128_t)limit;

	if ((uint64_t)sample < limit)
	{
		uint64_t reject = -limit % limit;
		while ((uint64_t)sample < reject)
			sample = prng_word() * (__uint128_t)limit;
	}

	return sample >> 64;
}

int prng_weighted(uint64_t w[], int count)
{
	uint64_t val;
	int ii;

	if (w[0] == 0)
	{
		for (ii = 1; ii <= count; ++ii)
		{
			w[0] += w[ii];
		}
	}

	val = prng_mod(w[0]);
	for (ii = 1; ii <= count; ++ii)
	{
		if (val < w[ii])
		{
			return ii;
		}
		val -= w[ii];
	}

	fprintf(stderr, "prng_weighted() got corrupted weights, w[0]=%llu\n",
		(long long unsigned)w[0]);
	abort();
}

/* ****************** */
/* benchmark planning */
/* ****************** */

int entry_cmp(const void *va, const void *vb)
{
	const struct entry *a = va, *b = vb;
	int ii, jj;

	/* First, sort IPv4 < IPv6. */
	ii = irc_in_addr_is_ipv4(&a->addr);
	jj = irc_in_addr_is_ipv4(&b->addr);
	if (ii != jj)
	{
		return jj - ii;
	}

	/* Next, sort mask < full < miss. */
	if (a->nbits != b->nbits)
	{
		if (a->nbits == 0) return 1;
		if (b->nbits == 0) return -1;
		if (a->nbits == 128) return 1;
		if (b->nbits == 128) return -1;
		/* else fall through */
	}

	/* Next, compare IP addresses. */
	for (ii = 0; ii < 8; ++ii)
	{
		if (a->addr.in6_16[ii] != b->addr.in6_16[ii])
		{
			int a_w = ntohs(a->addr.in6_16[ii]), b_w = ntohs(b->addr.in6_16[ii]);
			return a_w - b_w;
		}
	}

	/* We may have a::b/32 and a::b/48; the first is less. */
	return (int)a->nbits - (int)b->nbits;
}

/* Return negative if mask is too early to match ee, 0 if mask matches
 * ee, and positive if mask does not match ee for some other reason.
 */
int entry_cmp_mask(const struct entry *ee, const struct entry *mask)
{
	int ii;
	uint16_t ee_b, mm_b, ww;
	uint8_t nbits;

	for (ii = 0, nbits = 0; nbits < mask->nbits; ++ii)
	{
		nbits += 16;
		ee_b = ntohs(ee->addr.in6_16[ii]);
		mm_b = ntohs(mask->addr.in6_16[ii]);
		if (nbits >= mask->nbits)
		{
			ww = 0xffff << (nbits - mask->nbits);
			ee_b &= ww;
			mm_b &= ww;
		}
		/* If ee_b has some bit set that is clear in mm_b, *mask and
		 * every "lesser" mask will be too small to match ee_b.
		 */
		if (ee_b & ~mm_b) return -1;
		if (ee_b != mm_b) return 1;
	}

	return 0;
}

/* Returns the smallest index 0 <= ii < count such that *ee < table[base+ii].
 * If table[base+count-1] < *ee, then returns count.  However, if
 * *ee == table[base+ii] for some ii, then returns ~(uint64_t)0.
 */
uint64_t entry_find_slot(uint64_t base, uint64_t count, const struct entry *ee)
{
	uint64_t lo, hi;

	for (lo = 0, hi = count; lo + 1 < hi; )
	{
		uint64_t mid = (lo + hi) / 2;
		int cmp = entry_cmp(ee, &table[base+mid]);
		if (cmp < 0)
		{
			hi = mid;
		}
		else if (cmp > 0)
		{
			lo = mid + 1;
		}
		else
		{
			return -1;
		}
	}

	return lo;
}

uint64_t entry_hit(uint64_t base, uint64_t n_mask, uint64_t n_full, const struct entry *ee)
{
	void *ptr;
	uint64_t idx;
	int cmp;

	/* Search for an exact match first. */
	ptr = bsearch(ee, &table[base+n_mask], n_full, sizeof table[0], entry_cmp);
	if (ptr)
	{
		return (struct entry *)ptr - table - base;
	}

	/* Search for a mask covering the entry.
	 * Walk backwards from what would be the insertion point for ee
	 * until we find a match or the mask is too early to match.
	 */
	for (idx = entry_find_slot(base, n_mask, ee); ~idx; )
	{
		--idx;
		cmp = entry_cmp_mask(ee, &table[base+idx]);
		if (cmp == 0) return idx;
		if (cmp < 0) break;
	}

	/* We found nothing. */
	return -1;
}

void plan_sort(uint64_t base, uint64_t count)
{
	qsort(table + base, count, sizeof *table, entry_cmp);
}

void plan_v4(struct entry *ee, uint8_t nbits)
{
	uint64_t addr;

	memset(ee, 0, sizeof *ee);
	addr = prng_mod(((uint64_t)233)*256*256*256);
	ee->nbits = nbits;
	ee->addr.in6_16[5] = 0xffff;
	ee->addr.in6_16[6] = htons((addr >> 16) + 256);
	/* LSBs are random, so byte order does not matter. */
	ee->addr.in6_16[7] = addr & 0xffff;
}

void plan_v6(struct entry *ee, uint8_t nbits)
{
	uint64_t addr;

	memset(ee, 0, sizeof *ee);
	addr = prng_word() >> 4;
	ee->nbits = nbits;
	ee->addr.in6_16[0] = htons(0x2000 | (addr >> 48));
	ee->addr.in6_16[1] = (addr >> 32) & 0xffff;
	ee->addr.in6_16[2] = (addr >> 16) & 0xffff;
	ee->addr.in6_16[3] = addr & 0xffff;
	addr = prng_word();
	ee->addr.in6_16[4] = addr >> 48;
	ee->addr.in6_16[5] = (addr >> 32) & 0xffff;
	ee->addr.in6_16[6] = (addr >> 16) & 0xffff;
	ee->addr.in6_16[7] = addr & 0xffff;
}

void plan_v4_mask(struct entry *ee)
{
	plan_v4(ee, 103 + prng_weighted(v4_w, 17));

	/* Clear the "host" bits of the netmask. */
	if (ee->nbits < 112)
	{
		ee->addr.in6_16[7] = 0;
		ee->addr.in6_16[6] = htons(ntohs(ee->addr.in6_16[6]) & (0xffff << (112 - ee->nbits)));
	}
	else
	{
		ee->addr.in6_16[7] = htons(ntohs(ee->addr.in6_16[7]) & (0xffff << (128 - ee->nbits)));
	}
}

void plan_v6_mask(struct entry *ee)
{
	int idx;
	uint8_t nbits;

	switch ((idx = prng_weighted(v6_w, 19)))
	{
	case 1: nbits = 16; break;
	case 2: nbits = 32; break;
	case 3: nbits = 48; break;
	case 4: nbits = 64; break;
	default: nbits = idx + 44; break;
	}
	plan_v6(ee, nbits);

	/* Clear the "host" bits of the netmask. */
	for (idx = 7, nbits = 128 - ee->nbits; nbits > 0; --idx)
	{
		if (nbits > 15)
		{
			ee->addr.in6_16[idx] = 0;
			nbits -= 16;
		}
		else
		{
			ee->addr.in6_16[idx] = htons(ntohs(ee->addr.in6_16[idx])
				& ~(0xffff >> nbits));
			break;
		}
	}
}

/* Generate initial random entries. */
void plan_random(int do_hits)
{
	uint64_t ii, base;

	/* Generate initial random entries.
	 * If we loaded a table at startup, do not generate the mask or
	 * full-length entries.
	 */
	if (do_hits)
	{
		for (base = 0,   ii = 0; ii < v4_n_mask; ++ii)
			plan_v4_mask(&table[base+ii]);
		for (base += ii, ii = 0; ii < v4_n_full; ++ii)
			plan_v4(&table[base+ii], 128);
	}
	for (base = v4_n_mask + v4_n_full, ii = 0; ii < v4_n_miss; ++ii)
		plan_v4(&table[base+ii], 0);

	if (do_hits)
	{
		for (base += ii, ii = 0; ii < v6_n_mask; ++ii)
			plan_v6_mask(&table[base+ii]);
		for (base += ii, ii = 0; ii < v6_n_full; ++ii)
			plan_v6(&table[base+ii], 128);
	}
	for (base = v4_n_total + v6_n_mask + v6_n_full, ii = 0; ii < v6_n_miss; ++ii)
		plan_v6(&table[base+ii], 0);
}

/* Deletes table[base+drop] and inserts *ee before the old table[base+repl]. */
void plan_replace(uint64_t base, uint64_t drop, uint64_t repl, const struct entry *ee)
{
	if (drop < repl)
	{
		memmove(&table[base+drop], &table[base+drop+1], (repl-drop)*sizeof table[0]);
		memcpy(&table[base+repl-1], ee, sizeof table[0]);
	}
	else if (repl < drop)
	{
		memmove(&table[base+repl], &table[base+repl+1], (drop-repl)*sizeof table[0]);
		memcpy(&table[base+repl], ee, sizeof table[0]);
	}
	else /* how lucky! */
	{
		memcpy(&table[base+drop], ee, sizeof table[0]);
	}
}

/* Remove and replace duplicate entries, including false "miss" entries. */
void plan_unduplicate(uint64_t base, uint64_t n_mask, uint64_t n_full, uint64_t n_miss)
{
	const uint64_t n_total = n_mask + n_full + n_miss;
	struct entry ee_tmp;
	uint64_t ii, jj, t_base;
	int cmp;

	plan_sort(base, n_total);

	/* Handle duplicate masks. */
	for (ii = 0; ii + 1 < n_mask; ++ii)
	{
		if (entry_cmp(&table[base+ii], &table[base+ii+1])) continue;
		/* entries ii and ii+1 are identical; create a replacement. */
		do {
			plan_v4_mask(&ee_tmp);
			jj = entry_find_slot(base, n_mask, &ee_tmp);
		} while (!~jj);
		/* Drop entry ii+1 and insert ee_tmp at position jj. */
		plan_replace(base, ii+1, jj, &ee_tmp);
		--ii;
	}

	/* Handle duplicate full-length matches. */
	for (ii = 0, t_base = base + n_mask; ii + 1 < n_full; ++ii)
	{
		if (entry_cmp(&table[t_base+ii], &table[t_base+ii+1])) continue;
		do {
			plan_v4(&ee_tmp, 128);
			jj = entry_find_slot(t_base, n_full, &ee_tmp);
		} while (!~jj);
		plan_replace(t_base, ii+1, jj, &ee_tmp);
		--ii;
	}

	/* Handle duplicate or matched misses. */
	for (ii = 0, t_base += n_full; ii < n_miss; ++ii)
	{
		/* Keep it if no match and either no next "miss", or next "miss" differs. */
		jj = entry_hit(base, n_mask, n_full, &table[t_base+ii]);
		if (!~jj && ((ii + 1 == n_miss)
			|| (cmp = entry_cmp(&table[t_base+ii], &table[t_base+ii+1]))))
		{
			continue;
		}
		do {
			plan_v4(&ee_tmp, 0);
			/* Try again if ee_tmp is a repeat or there is a match. */
			jj = entry_find_slot(t_base, n_miss, &ee_tmp);
			if (~jj && ~entry_hit(base, n_mask, n_full, &ee_tmp))
			{
				jj = -1;
			}
		} while (!~jj);
		plan_replace(t_base, ii+1, jj, &ee_tmp);
		--ii;
	}
}

/* Assign initial values for table[ii].active. */
void plan_active(void)
{
	const char *text;
	uint64_t ii;

	for (ii = 0; ii < n_total; ++ii)
	{
		table[ii].active = table[ii].nbits ? ((prng_word() >> 32) < p_load) : 0;
		table[ii].orig_active = table[ii].active;

		text = (table[ii].nbits > 0 && table[ii].nbits < 128)
			? ircd_ntocidrmask(&table[ii].addr, table[ii].nbits)
			: ircd_ntoa(&table[ii].addr);
		strncpy(table[ii].text, text, sizeof(table[ii].text)-1);
	}
}

uint64_t do_plan(void)
{
	int need_table = !table;

	/* Summarize counts of entries. */
	v4_n_total = v4_n_mask + v4_n_full + v4_n_miss;
	v6_n_total = v6_n_mask + v6_n_full + v6_n_miss;
	n_mask = v4_n_mask + v6_n_mask;
	n_full = v4_n_full + v6_n_full;
	n_miss = v4_n_miss + v6_n_miss;
	n_total = v4_n_total + v6_n_total;

	/* Do we need to make a plan? */
	if (need_table)
	{
		table = calloc(n_total, sizeof *table);
		if (!table)
		{
			perror("unable to allocate table");
			exit(EXIT_FAILURE);
		}
	}

	plan_random(need_table);
	plan_unduplicate(0, v4_n_mask, v4_n_full, v4_n_miss);
	plan_unduplicate(v4_n_total, v6_n_mask, v6_n_full, v6_n_miss);

	/* Sort the plan and assign initial activation status. */
	plan_sort(0, n_total);
	plan_active();
	return n_total;
}

/* ******************** */
/* perform initial load */
/* ******************** */

uint64_t do_load(void)
{
	uint64_t ii, bound, count;

	for (ii = count = 0, bound = n_mask + n_full; ii < bound; ++ii)
	{
		if (table[ii].active)
		{
			++count;
			table_map(&table[ii], &table[ii]);
		}
	}

	return count;
}

/* **************** */
/* update the table */
/* **************** */

uint64_t do_updates(void)
{
	uint64_t count, bound;

	for (count = 0, bound = n_mask + n_full; !b_sig_flag; ++count)
	{
		uint64_t ii = prng_mod(bound);
		table[ii].active = !table[ii].active;
		table_map(&table[ii], table[ii].active ? &table[ii] : NULL);
	}
	return count;

}

/* *************** */
/* query the table */
/* *************** */

uint64_t do_lookups(void)
{

	uint64_t count;
	for (count = 0; !b_sig_flag; ++count)
	{
		uint64_t ii = prng_mod(n_total);
		void *res = table_lookup(&table[ii]);
#if defined(_DEBUG)
		void *exp = &table[ii];
		if (!table[ii].nbits || !table[ii].active) exp = NULL;
		if (res != exp)
		{
			fprintf(stderr, "do_lookups() got mismatch: %p != %p\n", res, exp);
			abort();
		}
#else
		(void)res;
#endif
	}
	return count;
}

/* ************************ */
/* reload the initial table */
/* ************************ */

uint64_t do_reload(void)
{
	uint64_t ii, bound, count;

	for (ii = count = 0, bound = n_mask + n_full; ii < bound; ++ii)
	{
		if (table[ii].orig_active)
		{
			++count;
			table_map(&table[ii], &table[ii]);
		}
	}

	return count;
}

/* ******************** */
/* command line helpers */
/* ******************** */

const struct option longopts[] = {
	{ "burst", required_argument, NULL, 'b' },
	{ "interval", required_argument, NULL, 'i' },
	{ "pload", required_argument, NULL, 'p' },
	{ "seed", required_argument, NULL, 's' },
	{ "verbosity", optional_argument, NULL, 'v' },
	{ "v4", required_argument, NULL, '4' },
	{ "v6", required_argument, NULL, '6' },
	{ "w4", required_argument, NULL, 'w' },
	{ "w6", required_argument, NULL, 'W' },
	{ NULL, 0, NULL, 0 }
};

int parse_weights(char *str, uint64_t w[], int count)
{
	int ii;
	char x_sep, *sep;

	w[0] = 0;
	for (ii = 1; ii <= count; ++ii)
	{
		x_sep = (ii == count) ? '\0' : ',';
		w[ii] = strtoull(str, &sep, 0);
		if (*sep != x_sep)
			return ii;
		str = sep + 1;
	}

	return 0;
}

void parse_argc(int argc, char *argv[])
{
	char *burst_file = NULL, *end;
	double interval = 5.0;
	double prob = 0.75;
	uint64_t seed = 12345;
	int opt;

	while (-1 != (opt = getopt_long(argc, argv, "b:4:6:W:i:p:s:w:v::", longopts, NULL)))
	{
		switch (opt)
		{
		case 'b':
			burst_file = strdup(optarg);
			break;
		case '4': /* --v4=mask,full,miss */
			v4_n_mask = strtoull(optarg, &end, 0);
			if (*end != ',' || v4_n_mask > 0x100000000) goto usage;
			v4_n_full = strtoull(end+1, &end, 0);
			if (*end != ',' || v4_n_full > 0x100000000) goto usage;
			v4_n_miss = strtoull(end+1, &end, 0);
			if (*end != '\0' || v4_n_miss > 0x100000000) goto usage;
			break;
		case '6': /* --v6=mask,full,miss */
			v6_n_mask = strtoull(optarg, &end, 0);
			if (*end != ',' || v6_n_mask > 0x100000000) goto usage;
			v6_n_full = strtoull(end+1, &end, 0);
			if (*end != ',' || v6_n_full > 0x100000000) goto usage;
			v6_n_miss = strtoull(end+1, &end, 0);
			if (*end != '\0' || v6_n_miss > 0x100000000) goto usage;
			break;
		case 'W': /* --w6=w1,w2,...,w19 */
			if (parse_weights(optarg, v6_w, 19)) goto usage;
			break;
		case 'i': /* --interval=n.m */
			interval = strtod(optarg, &end);
			if (*end != '\0' || interval <= 0) goto usage;
			break;
		case 'p': /* --pload=0.75 */
			prob = strtod(optarg, &end);
			if (*end != '\0' || prob < 0 || prob > 1) goto usage;
			break;
		case 's': /* --seed=<u> */
			seed = strtoull(optarg, &end, 0);
			if (*end != '\0') goto usage;
			break;
		case 'v': /* --verbosity[=n] */
			if (optarg)
			{
				verbose = strtoul(optarg, &end, 0);
				if (*end != '\0') goto usage;
			}
			else
			{
				++verbose;
			}
			break;
		case 'w': /* --w4=w1,w2,...,w17 */
			if (parse_weights(optarg, v4_w, 17)) goto usage;
			break;
		case '?':
		usage:
			fprintf(stdout,
				"Usage: %s [-i <interval>]\n"
				"Options:\n"
				" -i, --interval <t> Number of seconds to run update and lookup phases",
				argv[0]);
			/* fall through */
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (burst_file)
	{
		table_load(burst_file);
		free(burst_file);
	}

	p_load = lround(ldexp(prob, 32));
	b_interval.it_value.tv_sec = floor(interval);
	b_interval.it_value.tv_usec = lround(1e9 * (interval - b_interval.it_value.tv_sec));
	prng_seed(seed);
}

int main(int argc, char *argv[])
{
	parse_argc(argc, argv);

	table_init();
	bench_start();
	bench_report("plan", do_plan());
	bench_report("load", do_load());
	bench_report("updates", do_updates());
	bench_report("lookups", do_lookups());
	bench_report("reload", do_reload());

	return EXIT_SUCCESS;
}
